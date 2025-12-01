import logging
import socket
import threading
import time
from collections import defaultdict
from typing import Optional

from base_honeypot import BaseHoneypot, HoneypotSession
from infra.interfaces import HoneypotAction

logger = logging.getLogger(__name__)


class RedisHoneypot(BaseHoneypot):
    def __init__(self, port=0, action: HoneypotAction = None, config: dict = None):
        super().__init__(port, config)
        self.server_socket = None
        self.running = False
        self.action = action
        # In-memory store: {db_index: {key: value}}
        self.data_store = defaultdict(dict)
        self.start_time = time.time()

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", self.port))
        if self.port == 0:
            self.port = self.server_socket.getsockname()[1]

        self.server_socket.listen(100)
        self.running = True

        logger.info(f"Redis Honeypot running on port {self.port}")
        threading.Thread(target=self._listen, daemon=True).start()
        return self

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.server_socket.close()
            except OSError:
                pass
        logger.info("Redis Honeypot stopped")

    def _listen(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                threading.Thread(
                    target=self._handle_client, args=(client_socket, addr), daemon=True
                ).start()
            except OSError as e:
                if self.running:
                    logger.error(f"Socket error in _listen: {e}")
                    time.sleep(0.1)

    def _handle_client(self, client_socket, addr):
        logger.info(f"New connection from {addr}")
        session = HoneypotSession()
        session["client_ip"] = addr[0]
        # Track current database index for this connection (default 0)
        session["current_db"] = 0

        try:
            buffer = b""
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                buffer += data

                # Process commands (simple RESP parser)
                while b"\n" in buffer:
                    decoded = buffer.decode("utf-8", errors="ignore")
                    logger.info(f"DEBUG: Received buffer: {decoded!r}")

                    if not decoded.endswith("\n"):
                        # Wait for more data if we don't have a newline
                        pass

                    # Reset buffer for next command - initial approach
                    command_str = self._extract_command(decoded)
                    buffer = b""

                    if command_str:
                        logger.info(f"Redis command: {command_str}")
                        self.log_data(
                            session, {"method": "command", "command": command_str}
                        )

                        response = self._process_command(command_str, session)
                        logger.info(f"DEBUG: Sending response: {response!r}")
                        client_socket.sendall(response)
                    else:
                        # if we can't parse, we assume its garbage or incomplete
                        break

        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()

    def _extract_command(self, data: str) -> Optional[str]:
        """
        Extracts a human-readable command from RESP or inline format.
        """
        lines = [line.strip() for line in data.strip().split("\n") if line.strip()]
        if not lines:
            return None

        # Handle RESP array
        if lines[0].startswith("*"):
            # *2\r\n$3\r\nGET\r\n$3\r\n foo
            parts = []
            i = 1
            while i < len(lines):
                if lines[i].startswith("$"):
                    i += 1
                    if i < len(lines):
                        parts.append(lines[i])
                i += 1
            return " ".join(parts)

        # Handle inline command
        return lines[0]

    def _process_command(self, command: str, session: HoneypotSession) -> bytes:
        cmd_parts = command.split()
        if not cmd_parts:
            return b"-ERR unknown command\r\n"

        cmd = cmd_parts[0].upper()
        current_db = session.get("current_db", 0)

        if cmd == "AUTH":
            # Log the password attempt
            password = cmd_parts[1] if len(cmd_parts) > 1 else ""
            logger.info(f"AUTH attempt with password: {password}")
            # Always accept
            return b"+OK\r\n"

        elif cmd == "SELECT" and len(cmd_parts) >= 2:
            try:
                db_index = int(cmd_parts[1])
                session["current_db"] = db_index
                return b"+OK\r\n"
            except ValueError:
                return b"-ERR invalid DB index\r\n"

        elif cmd == "SET" and len(cmd_parts) >= 3:
            key = cmd_parts[1]
            value = " ".join(cmd_parts[2:])
            self.data_store[current_db][key] = value
            return b"+OK\r\n"

        elif cmd == "GET" and len(cmd_parts) >= 2:
            key = cmd_parts[1]
            val = self.data_store[current_db].get(key)
            if val is not None:
                return f"${len(val)}\r\n{val}\r\n".encode()
            pass

        elif cmd == "DEL" and len(cmd_parts) >= 2:
            count = 0
            for key in cmd_parts[1:]:
                if key in self.data_store[current_db]:
                    del self.data_store[current_db][key]
                    count += 1
            return f":{count}\r\n".encode()

        elif cmd == "KEYS":
            pattern = cmd_parts[1] if len(cmd_parts) > 1 else "*"
            # Simple implementation: only support * or exact match for now
            if pattern == "*":
                keys = list(self.data_store[current_db].keys())
            else:
                keys = [k for k in self.data_store[current_db].keys() if k == pattern]

            # Construct RESP array
            resp = f"*{len(keys)}\r\n"
            for k in keys:
                resp += f"${len(k)}\r\n{k}\r\n"
            return resp.encode()

        elif cmd == "FLUSHDB":
            self.data_store[current_db].clear()
            return b"+OK\r\n"

        elif cmd == "FLUSHALL":
            self.data_store.clear()
            return b"+OK\r\n"

        elif cmd == "INFO":
            uptime = int(time.time() - self.start_time)
            info = (
                "# Server\r\n"
                "redis_version:6.2.6\r\n"
                "os:Linux\r\n"
                "arch_bits:64\r\n"
                "multiplexing_api:epoll\r\n"
                f"uptime_in_seconds:{uptime}\r\n"
                "uptime_in_days:0\r\n"
                "# Clients\r\n"
                "connected_clients:1\r\n"
                "# Memory\r\n"
                "used_memory:1024000\r\n"
                "used_memory_human:1.00M\r\n"
                "# Persistence\r\n"
                "loading:0\r\n"
                "# Stats\r\n"
                "total_connections_received:1\r\n"
                "total_commands_processed:1\r\n"
                "# Replication\r\n"
                "role:master\r\n"
                "connected_slaves:0\r\n"
                "# CPU\r\n"
                "used_cpu_sys:0.50\r\n"
                "used_cpu_user:0.50\r\n"
                "# Keyspace\r\n"
                f"db{current_db}:keys={len(self.data_store[current_db])},expires=0,avg_ttl=0\r\n"
            )
            return f"${len(info)}\r\n{info}\r\n".encode()

        elif cmd == "COMMAND":
            # Return empty array to satisfy redis-cli introspection
            return b"*0\r\n"

        if self.action:
            result = self.action.query(command, session)
            output = result["output"] if isinstance(result, dict) else str(result)

            # Unescape literal \r\n from JSON dataset
            if isinstance(output, str):
                output = output.replace("\\r", "\r").replace("\\n", "\n")

            # If the output looks like RESP, return it directly
            if (
                output.startswith("+")
                or output.startswith("-")
                or output.startswith("$")
                or output.startswith(":")
                or output.startswith("*")
            ):
                return output.encode() if isinstance(output, str) else output

            # simple one-line response, +OK style
            if "\n" not in output and len(output) < 100:
                return f"+{output}\r\n".encode()
            else:
                return f"${len(output)}\r\n{output}\r\n".encode()

        # Fallback hardcoded responses if no action/dataset match
        if cmd == "PING":
            return b"+PONG\r\n"

        return b"+OK\r\n"

    def handle_request(self, ctx: dict) -> tuple:
        # Not used for TCP honeypots usually, but required by base
        return 200, {}, b""
