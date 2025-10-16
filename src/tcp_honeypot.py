import logging
import os
import threading

from base_honeypot import BaseHoneypot
from infra.interfaces import HoneypotAction
import socket


logger = logging.getLogger(__name__)


class TCPHoneypot(BaseHoneypot):
    def __init__(
        self,
        port: int = None,
        action: HoneypotAction = None,
        config: dict = None,
    ):
        super().__init__(port, config)
        self._action = action
        self._server_socket = None
        self._running = False
        self._thread = None

    def honeypot_type(self) -> str:
        return "tcp"

    def start(self):
        logger.info(f"TCP Honeypot started on port {self.port}")
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.bind(("0.0.0.0", self.port))
        cfg_dir = (self.config or {}).get("config_dir")
        if cfg_dir:
            try:
                with open(os.path.join(cfg_dir, "bound_port"), "w") as f:
                    f.write(str(self.port))
            except OSError:
                pass
        self._server_socket.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._accept_connections, daemon=True)
        self._thread.start()
        logger.info(f"TCP Honeypot started and listening on port {self.port}")

    def _accept_connections(self):
        while self._running:
            try:
                client_socket, addr = self._server_socket.accept()
                client_socket.settimeout(120)
                logger.info(f"Connection accepted from {addr}")

                session = self._action.connect({"client_ip": addr[0]})
                self.log_login(session, {"client_ip": addr[0], "client_port": addr[1]})
                with client_socket:
                    while self._running:
                        logger.info(f"Session {session.session_id} is active")
                        data = client_socket.recv(1024)
                        if not data:
                            break
                        self.log_data(session, {"command": data.decode()})
                        response = self._action.query(data.decode(), session)
                        client_socket.sendall(response.encode())
                logger.info(f"Session {session.session_id} is closed")
            except OSError:
                break

    def stop(self):
        self._running = False
        if self._server_socket:
            self._server_socket.close()
            self._server_socket = None
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("TCP Honeypot stopped")
