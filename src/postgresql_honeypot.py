import logging
import socket
import threading
from typing import Tuple, Dict, Any

from base_honeypot import BaseHoneypot

logger = logging.getLogger(__name__)


class PostgresHoneypot(BaseHoneypot):
    """
    A simple Postgresql honeypot that accepts TCP connections and mimics
    the initial handshake of a Postgresql server.
    """

    def __init__(self, port: int, action: Any, config: dict):
        super().__init__(port=port, config=config)
        self.action = action
        self.host: str = config.get("host", "0.0.0.0")
        self.listen_port: int = port
        self.server_socket: socket.socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sessions: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.running: bool = False

    def start(self) -> None:
        self.server_socket.bind((self.host, self.listen_port))
        self.server_socket.listen()
        self.bound_port = self.server_socket.getsockname()[1]
        self.running = True
        logger.info(f"PostgresHoneypot running on {self.host}:{self.bound_port}")
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self) -> None:
        self.running = False
        try:
            self.server_socket.close()
        except Exception as e:
            logger.warning(f"Error closing server socket: {e}")
        logger.info("PostgresHoneypot stopped")

    def _accept_loop(self) -> None:
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                logger.info(f"Connection from {addr}")
                self.sessions[addr] = {"addr": addr}
                threading.Thread(
                    target=self._handle_client, args=(client_socket, addr), daemon=True
                ).start()
            except OSError as e:
                logger.warning(f"Accept failed: {e}")
            except Exception as e:
                logger.exception(f"Unexpected error in accept loop: {e}")

    def _handle_client(
        self, client_socket: socket.socket, addr: Tuple[str, int]
    ) -> None:
        try:
            for _ in range(2):  # At most two initial requests: SSL and GSSENC
                data = client_socket.recv(1024)
                if not data:
                    return
                logger.info(f"[{addr}] Received raw bytes: {data.hex()}")

                # SSLRequest (0x2f) or GSSENCRequest (0x30)
                if (
                    len(data) == 8
                    and data[:4] == b"\x00\x00\x00\x08"
                    and data[4:7] == b"\x04\xd2\x16"
                    and data[7] in (0x2F, 0x30)
                ):
                    client_socket.sendall(b"N")
                    continue  # Accept another initial request if needed

                break

            client_socket.sendall(
                b"R\x00\x00\x00\x08\x00\x00\x00\x00"
            )  # AuthenticationOk
            client_socket.sendall(b"Z\x00\x00\x00\x05I")  # ReadyForQuery

            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                logger.info(f"[{addr}] Received post-connect bytes: {data.hex()}")
        except OSError as e:
            logger.warning(f"[{addr}] Client error: {e}")
        except Exception as e:
            logger.exception(f"[{addr}] Unexpected error in client handler: {e}")
        finally:
            try:
                client_socket.close()
            except Exception as e:
                logger.warning(f"[{addr}] Error closing client socket: {e}")
