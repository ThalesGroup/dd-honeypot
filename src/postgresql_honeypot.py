import socket
import threading
import logging
from typing import Tuple, Dict, Optional
from base_honeypot import BaseHoneypot

logging.basicConfig(level=logging.INFO)


class PostgresHoneypot(BaseHoneypot):
    def __init__(self, port, action, config):
        super().__init__(port=port, config=config)
        self.action = action
        self.host = config.get("host", "0.0.0.0")
        self.listen_port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sessions: Dict[Tuple[str, int], Dict] = {}

    def start(self):
        self.server_socket.bind((self.host, self.listen_port))
        self.server_socket.listen()
        self.bound_port = self.server_socket.getsockname()[1]
        self.running = True
        logging.info(f"PostgresHoneypot running on {self.host}:{self.bound_port}")
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self.running = False
        self.server_socket.close()
        logging.info("PostgresHoneypot stopped")

    def _accept_loop(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                logging.info(f"Connection from {addr}")
                self.sessions[addr] = {"addr": addr}
                threading.Thread(
                    target=self._handle_client, args=(client_socket, addr), daemon=True
                ).start()
            except Exception as e:
                logging.warning(f"Accept failed: {e}")

    def _handle_client(self, client_socket: socket.socket, addr: Tuple[str, int]):
        try:
            data = client_socket.recv(1024)
            if data:
                logging.info(f"Received raw bytes: {data.hex()}")
                query = self._extract_query(data)
                logging.info(f"Simulated SQL: {query}")

                session = self.sessions.get(addr, {})

                if self.log_data:
                    self.log_data(session, {"query": query})

                if self.action:
                    try:
                        self.action.connect({"client": addr})
                        response = self.action.query(query, session=session)
                        logging.info(f"LLM response: {response}")
                    except Exception as e:
                        logging.warning(f"Action handler failed: {e}")

                client_socket.sendall(self._build_fake_row("hello_from_fake_pg"))
        except Exception as e:
            logging.warning(f"Client error: {e}")
        finally:
            client_socket.close()

    def _extract_query(self, data: bytes) -> str:
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return "<unreadable query>"

    def _build_fake_row(self, value: str) -> bytes:
        return b"Z"
