import socket
import threading
import logging
from typing import Tuple

logging.basicConfig(level=logging.INFO)


class PostgresHoneypot:
    def __init__(self, host="127.0.0.1", port=0):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        self.bound_port = self.server_socket.getsockname()[
            1
        ]  #  Dynamic port after bind
        self.running = True
        logging.info(
            f"PostgresHoneypot running on {self.host}:{self.bound_port}"
        )  #  Use actual port
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                logging.info(f"Connection from {addr}")
                threading.Thread(
                    target=self._handle_client, args=(client_socket,), daemon=True
                ).start()
            except Exception as e:
                logging.warning(f"Accept failed: {e}")

    def _handle_client(self, client_socket: socket.socket):
        try:
            data = client_socket.recv(1024)
            if data:
                logging.info(f"Received raw bytes: {data.hex()}")
                query = self._extract_query(data)
                logging.info(f"Simulated SQL: {query}")

                # Always return a fake response
                fake_response = self._build_fake_row("hello_from_fake_pg")
                client_socket.sendall(fake_response)
        except Exception as e:
            logging.warning(f"Client error: {e}")
        finally:
            client_socket.close()

    def _extract_query(self, data: bytes) -> str:
        # Very basic simulation for demo purposes only (not real protocol parsing)
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return "<unreadable query>"

    def _build_fake_row(self, value: str) -> bytes:
        # Not a real Postgres protocol response — just enough to fake psycopg2
        return b"Z"  # Dummy 'ReadyForQuery' message (Z)

    def stop(self):
        self.running = False
        self.server_socket.close()
        logging.info("PostgresHoneypot stopped")
