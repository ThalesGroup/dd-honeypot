import json
import logging
import os
import socket
import struct
import threading
import time
from typing import Optional, List, Tuple

from base_honeypot import BaseHoneypot, HoneypotSession
from infra.interfaces import HoneypotAction

# Postgresql protocol constants
# Message types (frontend)
MSG_STARTUP = b"\x00"
MSG_QUERY = b"Q"
MSG_PARSE = b"P"
MSG_BIND = b"B"
MSG_DESCRIBE = b"D"
MSG_EXECUTE = b"E"
MSG_SYNC = b"S"
MSG_TERMINATE = b"X"
MSG_PASSWORD = b"p"
MSG_SSL_REQUEST = b"\x04\xd2\x16/"
MSG_GSSENC_REQUEST = b"\x04\xd2\x16\x30"

# Message types (backend)
MSG_AUTH_OK = b"R"
MSG_ERROR_RESPONSE = b"E"
MSG_PARAMETER_STATUS = b"S"
MSG_BACKEND_KEY_DATA = b"K"
MSG_READY_FOR_QUERY = b"Z"
MSG_ROW_DESCRIPTION = b"T"
MSG_DATA_ROW = b"D"
MSG_COMMAND_COMPLETE = b"C"
MSG_PARSE_COMPLETE = b"1"
MSG_BIND_COMPLETE = b"2"
MSG_PARAMETER_DESCRIPTION = b"t"
MSG_NO_DATA = b"n"
MSG_NOTICE_RESPONSE = b"N"

# Transaction status indicators
TRANS_IDLE = b"I"
TRANS_IN_TRANS = b"T"
TRANS_IN_ERROR = b"E"

# Field identifier codes for error and notice messages
ERROR_SEVERITY = b"S"
ERROR_CODE = b"C"
ERROR_MESSAGE = b"M"
ERROR_DETAIL = b"D"
ERROR_HINT = b"H"

# Postgresql error codes
ERRCODE_INTERNAL_ERROR = b"XX000"
ERRCODE_SYNTAX_ERROR = b"42601"

# Postgresql OIDs for common types
OID_INT4 = 23
OID_TEXT = 25


class PostgresHoneypot(BaseHoneypot):
    """
    A realistic Postgresql honeypot that accepts TCP connections, handles Postgresql
    protocol messages, and responds to SQL queries. Compatible with psycopg2.
    """

    def __init__(
        self,
        port: int = None,
        action: Optional[HoneypotAction] = None,
        config: dict = None,
    ):
        super().__init__(port, config)
        self._action = action
        self._thread = None
        self._sock = None
        self._running = False
        self._sessions = {}
        self._server_pid = os.getpid()  # Use the current process ID
        self._server_key = 12345  # random number for the backend key

    def start(self):
        def run_server():
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.port))
            self.port = self._sock.getsockname()[1]
            self._sock.listen(5)
            self._running = True
            logging.info(f"PostgresHoneypot running on 0.0.0.0:{self.port}")
            while self._running:
                try:
                    client, addr = self._sock.accept()
                    threading.Thread(
                        target=self.handle_client, args=(client, addr), daemon=True
                    ).start()
                except Exception as e:
                    logging.warning(f"Accept failed: {e}")

        self._thread = threading.Thread(target=run_server, daemon=True)
        self._thread.start()
        self.wait_until_ready()
        return self

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()
            self._sock = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        logging.info("PostgresHoneypot stopped")

    def _read_message(
        self, client: socket.socket
    ) -> Tuple[Optional[bytes], Optional[bytes]]:
        """
        Read a message from the client socket
        Returns: (message_type, message_body)
        """
        try:
            message_type = client.recv(1)
            if not message_type:
                return None, None  # Client disconnected

            # Special case: handling SSL and GSSENC requests that might come in the middle of a session
            # They have a special format where the first byte is 0x00
            if message_type == b"\x00":
                # Read 7 more bytes to see if it's an SSL/GSSENC request
                more_bytes = client.recv(7)
                if len(more_bytes) != 7:
                    return None, None  # Client disconnected

                # Reconstruct the full message
                full_message = message_type + more_bytes

                # Check for SSL request: 00 00 00 08 04 d2 16 2f
                if full_message == b"\x00\x00\x00\x08\x04\xd2\x16/":
                    logging.info(
                        "SSL request received mid-session, responding with 'N'"
                    )
                    client.sendall(b"N")
                    return b"S", b"SSL_REQUEST"  # Special marker for our processing

                # Check for GSSENC request: 00 00 00 08 04 d2 16 30
                elif full_message == b"\x00\x00\x00\x08\x04\xd2\x16\x30":
                    logging.info(
                        "GSSENC request received mid-session, responding with 'N'"
                    )
                    client.sendall(b"N")
                    return b"G", b"GSSENC_REQUEST"  # Special marker for our processing

                # If it's not SSL/GSSENC, it's an unknown message format
                return None, None

            # Normal message processing
            # Then read the message length (4 bytes)
            length_bytes = client.recv(4)
            if len(length_bytes) != 4:
                return None, None

            # Calculate length (length includes itself but not message type)
            length = struct.unpack("!I", length_bytes)[0] - 4

            message_body = b""
            while len(message_body) < length:
                chunk = client.recv(min(4096, length - len(message_body)))
                if not chunk:
                    break
                message_body += chunk

            return message_type, message_body
        except ConnectionResetError:
            logging.debug("Connection reset by client while reading message")
            return None, None
        except BrokenPipeError:
            logging.debug("Broken pipe while reading message")
            return None, None
        except socket.error as e:
            if "Connection reset" in str(e) or "Broken pipe" in str(e):
                logging.debug(f"Client disconnected: {e}")
            else:
                logging.error(f"Socket error while reading message: {e}")
            return None, None
        except Exception as e:
            if "Connection reset" in str(e) or "Broken pipe" in str(e):
                logging.debug(f"Client disconnected: {e}")
            else:
                logging.error(f"Error reading message: {e}")
            return None, None

    def _send_message(
        self, client: socket.socket, message_type: bytes, message_body: bytes
    ) -> bool:
        """Send a message to the client socket"""
        try:
            length = len(message_body) + 4

            message = message_type + struct.pack("!I", length) + message_body

            client.sendall(message)
            return True
        except BrokenPipeError:
            logging.debug("Client disconnected while sending message")
            return False
        except ConnectionResetError:
            logging.debug("Connection reset by client while sending message")
            return False
        except Exception as e:
            if "Broken pipe" in str(e) or "Connection reset" in str(e):
                logging.debug(f"Client disconnected: {e}")
            else:
                logging.error(f"Error sending message: {e}")
            return False

    def _send_error(
        self,
        client: socket.socket,
        code: bytes = ERRCODE_INTERNAL_ERROR,
        message: str = "Internal server error",
        severity: str = "ERROR",
    ) -> bool:
        """Send an error message to the client"""
        # Build the error message body with field identifiers and values
        body = (
            ERROR_SEVERITY
            + severity.encode()
            + b"\0"
            + ERROR_CODE
            + code
            + b"\0"
            + ERROR_MESSAGE
            + message.encode()
            + b"\0"
            + b"\0"  # Null terminator for the entire message
        )

        return self._send_message(client, MSG_ERROR_RESPONSE, body)

    def _send_ready_for_query(
        self, client: socket.socket, status: bytes = TRANS_IDLE
    ) -> bool:
        """Send ReadyForQuery message"""
        return self._send_message(client, MSG_READY_FOR_QUERY, status)

    def _send_parameter_status(
        self, client: socket.socket, name: str, value: str
    ) -> bool:
        """Send a ParameterStatus message"""
        body = name.encode() + b"\0" + value.encode() + b"\0"
        return self._send_message(client, MSG_PARAMETER_STATUS, body)

    def _send_backend_key_data(self, client: socket.socket) -> bool:
        """Send BackendKeyData message with process ID and secret key"""
        body = struct.pack("!II", self._server_pid, self._server_key)
        return self._send_message(client, MSG_BACKEND_KEY_DATA, body)

    def _send_authentication_ok(self, client: socket.socket) -> bool:
        """Send AuthenticationOk message"""
        body = struct.pack("!I", 0)  # Auth type 0 = success
        return self._send_message(client, MSG_AUTH_OK, body)

    def _send_row_description(
        self, client: socket.socket, columns: List[Tuple[str, int]]
    ) -> bool:
        """
        Send RowDescription message with column information

        Args:
            client: Client socket
            columns: List of (name, type_oid) tuples
        """
        body = struct.pack("!H", len(columns))

        for name, type_oid in columns:
            body += name.encode() + b"\0"

            body += struct.pack("!I", 0)

            body += struct.pack("!H", 0)

            body += struct.pack("!I", type_oid)

            type_size = 4 if type_oid == OID_INT4 else -1
            body += struct.pack("!h", type_size)

            body += struct.pack("!I", 0xFFFFFFFF)

            body += struct.pack("!H", 0)

        return self._send_message(client, MSG_ROW_DESCRIPTION, body)

    def _send_data_row(
        self, client: socket.socket, values: List[Optional[str]]
    ) -> bool:
        """
        Send a DataRow message with values

        Args:
            client: Client socket
            values: List of column values (None for NULL)
        """
        body = struct.pack("!H", len(values))

        for value in values:
            if value is None:
                body += struct.pack("!i", -1)
            else:
                value_str = str(value).encode("utf-8")
                body += struct.pack("!I", len(value_str)) + value_str

        return self._send_message(client, MSG_DATA_ROW, body)

    def _send_command_complete(self, client: socket.socket, tag: str) -> bool:
        """
        Send a CommandComplete message

        Args:
            client: Client socket
            tag: Command tag (e.g., 'SELECT 1')
        """
        body = tag.encode() + b"\0"

        return self._send_message(client, MSG_COMMAND_COMPLETE, body)

    def _send_parse_complete(self, client: socket.socket) -> bool:
        """Send ParseComplete message"""
        return self._send_message(client, MSG_PARSE_COMPLETE, b"")

    def _send_bind_complete(self, client: socket.socket) -> bool:
        """Send BindComplete message"""
        return self._send_message(client, MSG_BIND_COMPLETE, b"")

    def _send_parameter_description(
        self, client: socket.socket, param_types: List[int] = None
    ) -> bool:
        """Send ParameterDescription message"""
        if not param_types:
            param_types = []

        body = struct.pack("!H", len(param_types))

        for type_oid in param_types:
            body += struct.pack("!I", type_oid)

        return self._send_message(client, MSG_PARAMETER_DESCRIPTION, body)

    def _send_no_data(self, client: socket.socket) -> bool:
        """Send NoData message"""
        return self._send_message(client, MSG_NO_DATA, b"")

    def handle_client(self, client, addr):
        session = {
            "user": None,
            "database": "postgres",
            "statements": {},
            "portals": {},
        }
        try:
            logging.info(f"Connection from {addr}")

            length_bytes = client.recv(4)
            if not length_bytes or len(length_bytes) != 4:
                client.close()
                return

            length = struct.unpack("!I", length_bytes)[0]

            if length == 8:
                magic_bytes = client.recv(4)

                # Handle SSL request: 04 d2 16 2f
                if magic_bytes == b"\x04\xd2\x16/":
                    logging.info("SSL request received, responding with 'N'")
                    client.sendall(b"N")

                    length_bytes = client.recv(4)
                    if not length_bytes or len(length_bytes) != 4:
                        client.close()
                        return

                    length = struct.unpack("!I", length_bytes)[0]

                # Handle GSSENC request: 04 d2 16 30
                elif magic_bytes == b"\x04\xd2\x16\x30":
                    logging.info("GSSENC request received, responding with 'N'")
                    client.sendall(b"N")

                    length_bytes = client.recv(4)
                    if not length_bytes or len(length_bytes) != 4:
                        client.close()
                        return

                    length = struct.unpack("!I", length_bytes)[0]

            # Read the rest of the startup message
            body = client.recv(length - 4)
            if not body:
                client.close()
                return

            # Parse the startup message parameters
            # Format: protocol_version(4) + key(n) + \0 + value(n) + \0 + ... + \0
            protocol_version = struct.unpack("!I", body[:4])[0]
            params = body[4:].split(b"\x00")

            for i in range(0, len(params) - 1, 2):
                if i + 1 < len(params):
                    key = params[i].decode(errors="ignore")
                    value = params[i + 1].decode(errors="ignore")
                    session[key] = value
                    if key == "user":
                        session["user"] = value
                    elif key == "database":
                        session["database"] = value

            logging.info(
                f"Postgresql connection: user={session.get('user')}, database={session.get('database')}"
            )

            if not self._send_authentication_ok(client):
                return

            if not self._send_backend_key_data(client):
                return

            if not self._send_parameter_status(client, "server_version", "15.0"):
                return

            if not self._send_parameter_status(client, "client_encoding", "UTF8"):
                return

            if not self._send_parameter_status(client, "server_encoding", "UTF8"):
                return

            if not self._send_parameter_status(client, "DateStyle", "ISO, MDY"):
                return

            if not self._send_parameter_status(client, "integer_datetimes", "on"):
                return

            if not self._send_parameter_status(
                client, "standard_conforming_strings", "on"
            ):
                return

            if not self._send_parameter_status(client, "application_name", ""):
                return

            if not self._send_ready_for_query(client):
                return

            while True:
                message_type, body = self._read_message(client)
                if not message_type:
                    break

                logging.info(f"[{addr}] Received message type: {message_type}")

                if message_type == MSG_QUERY:
                    self._handle_simple_query(client, body, session)

                elif message_type == MSG_PARSE:
                    self._handle_parse(client, body, session)

                elif message_type == MSG_BIND:
                    self._handle_bind(client, body, session)

                elif message_type == MSG_DESCRIBE:
                    self._handle_describe(client, body, session)

                elif message_type == MSG_EXECUTE:
                    self._handle_execute(client, body, session)

                elif message_type == MSG_SYNC:
                    self._send_ready_for_query(client)

                elif message_type == MSG_TERMINATE:
                    break

                # Special handling for our custom message types for SSL and GSSENC requests
                elif message_type == b"S" and body == b"SSL_REQUEST":
                    pass

                elif message_type == b"G" and body == b"GSSENC_REQUEST":
                    pass

                else:
                    logging.info(f"Ignoring unknown message type: {message_type}")
                    self._send_ready_for_query(client)

        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
        finally:
            client.close()

    def _handle_simple_query(
        self, client: socket.socket, body: bytes, session: dict
    ) -> None:
        """Handle a simple query message"""
        query = body[:-1].decode("utf-8")
        logging.info(f"Simple query: {query}")

        self._log_query(session, query)

        if query.strip().upper() in ["SELECT 1", "SELECT 1;"]:
            self._send_row_description(client, [("?column?", OID_INT4)])
            self._send_data_row(client, ["1"])
            self._send_command_complete(client, "SELECT 1")
        else:
            result = self._process_query(query, session)

            if result:
                self._send_query_result(client, result)

        self._send_ready_for_query(client)

    def _handle_parse(self, client: socket.socket, body: bytes, session: dict) -> None:
        """Handle a parse message"""
        # Parse message format:
        # - String: statement name
        # - String: query
        # - Int16: number of parameter types
        # - For each parameter type:
        #   - Int32: parameter type OID, or 0 for unspecified

        # Extract statement name
        null_pos = body.find(b"\0")
        if null_pos == -1:
            self._send_error(client, message="Invalid Parse message")
            return

        statement_name = body[:null_pos].decode("utf-8", errors="ignore")
        rest = body[null_pos + 1 :]

        # Extract query
        null_pos = rest.find(b"\0")
        if null_pos == -1:
            self._send_error(client, message="Invalid Parse message")
            return

        query = rest[:null_pos].decode("utf-8", errors="ignore")
        rest = rest[null_pos + 1 :]

        # Extract parameter types (we'll ignore these for now)
        if len(rest) >= 2:
            num_params = struct.unpack("!H", rest[:2])[0]

        # Store the parsed statement
        session["statements"][statement_name] = {"query": query}

        logging.info(f"Parsed statement '{statement_name}': {query}")

        self._send_parse_complete(client)

    def _handle_bind(self, client: socket.socket, body: bytes, session: dict) -> None:
        """Handle a bind message"""

        null_pos = body.find(b"\0")
        if null_pos == -1:
            self._send_error(client, message="Invalid Bind message")
            return

        portal_name = body[:null_pos].decode("utf-8", errors="ignore")
        rest = body[null_pos + 1 :]

        null_pos = rest.find(b"\0")
        if null_pos == -1:
            self._send_error(client, message="Invalid Bind message")
            return

        statement_name = rest[:null_pos].decode("utf-8", errors="ignore")

        session["portals"][portal_name] = statement_name

        logging.info(f"Bound portal '{portal_name}' to statement '{statement_name}'")

        self._send_bind_complete(client)

    def _handle_describe(
        self, client: socket.socket, body: bytes, session: dict
    ) -> None:
        """Handle a describe message"""
        if not body:
            self._send_error(client, message="Invalid Describe message")
            return

        target_type = body[0:1]
        name = body[1:-1].decode("utf-8", errors="ignore")  # Remove null terminator

        query = None
        if target_type == b"S":
            statement = session["statements"].get(name)
            if statement:
                query = statement.get("query")
        else:
            statement_name = session["portals"].get(name)
            if statement_name:
                statement = session["statements"].get(statement_name)
                if statement:
                    query = statement.get("query")

        if query:
            logging.info(
                f"Describing {'statement' if target_type == b'S' else 'portal'} '{name}': {query}"
            )

            self._send_parameter_description(client)

            if query.strip().upper() in ["SELECT 1", "SELECT 1;"]:
                self._send_row_description(client, [("?column?", OID_INT4)])
            else:
                self._send_row_description(client, [("result", OID_TEXT)])
        else:
            self._send_no_data(client)

    def _handle_execute(
        self, client: socket.socket, body: bytes, session: dict
    ) -> None:
        """Handle an execute message"""
        null_pos = body.find(b"\0")
        if null_pos == -1:
            self._send_error(client, message="Invalid Execute message")
            return

        portal_name = body[:null_pos].decode("utf-8", errors="ignore")

        query = None
        statement_name = session["portals"].get(portal_name)
        if statement_name:
            statement = session["statements"].get(statement_name)
            if statement:
                query = statement.get("query")

        if query:
            logging.info(f"Executing portal '{portal_name}': {query}")

            if query.strip().upper() in ["SELECT 1", "SELECT 1;"]:
                self._send_data_row(client, ["1"])
                self._send_command_complete(client, "SELECT 1")
            else:
                result = self._process_query(query, session)

                if result:
                    if "columns" in result and "rows" in result:
                        for row in result["rows"]:
                            self._send_data_row(client, row)

                    if "tag" in result:
                        self._send_command_complete(client, result["tag"])
                    else:
                        self._send_command_complete(
                            client, f"SELECT {len(result.get('rows', []))}"
                        )
        else:
            self._send_command_complete(client, "SELECT 0")

    def _process_query(self, query: str, session: dict) -> dict:

        normalized_query = query.strip().upper()

        if normalized_query in ["SELECT 1", "SELECT 1;"]:
            return {
                "columns": [("?column?", OID_INT4)],
                "rows": [["1"]],
                "tag": "SELECT 1",
            }

        elif "PG_VERSION" in normalized_query:
            return {
                "columns": [("version", OID_TEXT)],
                "rows": [["Postgresql 15.0"]],
                "tag": "SELECT 1",
            }

        elif normalized_query in [
            "BEGIN",
            "BEGIN;",
            "START TRANSACTION",
            "START TRANSACTION;",
        ]:
            return {"tag": "BEGIN"}

        elif normalized_query in ["COMMIT", "COMMIT;", "END", "END;"]:
            return {"tag": "COMMIT"}

        elif normalized_query in ["ROLLBACK", "ROLLBACK;"]:
            return {"tag": "ROLLBACK"}

        elif "SHOW" in normalized_query:
            param = query.strip().upper().replace("SHOW", "").strip()
            return {
                "columns": [(param.lower(), OID_TEXT)],
                "rows": [["on" if "DATE" in param else "UTF8"]],
                "tag": "SHOW",
            }

        if self._action and hasattr(self._action, "query"):
            try:
                response = self._action.query(query, HoneypotSession(session))
                # Try to parse the response as JSON rows
                if isinstance(response, dict) and "output" in response:
                    try:
                        data = json.loads(response["output"])
                        if isinstance(data, list) and data:
                            columns = [(col, OID_TEXT) for col in data[0].keys()]
                            rows = [
                                [str(row.get(col[0], "")) for col in columns]
                                for row in data
                            ]
                            return {
                                "columns": columns,
                                "rows": rows,
                                "tag": f"SELECT {len(rows)}",
                            }
                    except (json.JSONDecodeError, AttributeError, KeyError):
                        pass
            except Exception as e:
                logging.error(f"Error in action handler: {e}")

        # Default response
        return {"columns": [("result", OID_TEXT)], "rows": [["OK"]], "tag": "SELECT 1"}

    def _send_query_result(self, client: socket.socket, result: dict) -> None:
        """Send a query result to the client"""
        if "columns" in result:
            self._send_row_description(client, result["columns"])

            if "rows" in result:
                for row in result["rows"]:
                    self._send_data_row(client, row)

        if "tag" in result:
            self._send_command_complete(client, result["tag"])
        else:
            self._send_command_complete(client, f"SELECT {len(result.get('rows', []))}")

    def _log_query(self, session, query):
        """Log a SQL query with session information"""
        logging.info(
            f"Postgresql honeypot: user={session.get('user')}, db={session.get('database')}, query={query}"
        )
        self.log_data(session, {"query": query})
        if self.action and hasattr(self.action, "log_data"):
            self.action.log_data(session, {"query": query})

    @property
    def bound_port(self):
        """Get the bound port number"""
        return self.port

    @property
    def action(self):
        """Get the action handler"""
        return self._action

    def wait_until_ready(self, timeout=5):
        """Wait until the server is ready to accept connections"""
        start = time.time()
        while self.port == 0 and time.time() - start < timeout:
            time.sleep(0.05)
        return self.port != 0
