import logging
import threading
import socket
from time import sleep

import pytest

from infra.interfaces import HoneypotAction
from base_honeypot import BaseHoneypot, HoneypotSession
from honeypot_utils import allocate_port
from llm_utils import InvokeLimiter

logger = logging.getLogger(__name__)


class HoneypotTest(BaseHoneypot):

    class BufferSessionDataAction(HoneypotAction):
        """
        A concrete implementation of `HoneypotAction` that buffers session data.
        This class appends query data to the session's `data` field and returns the updated value.
        """

        def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
            logging.info("Querying with action. Session ID: %s", session.session_id)
            if "data" not in session:
                session["data"] = ""
            session["data"] += query
            return session["data"]

    def __init__(self, port: int = None):
        super().__init__(port)
        self._action = self.BufferSessionDataAction()
        self._server_socket = None
        self._running = False
        self._thread = None

    def start(self):
        logger.info(f"Test Honeypot started on port {self.port}")
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.bind(("0.0.0.0", self.port))
        self._server_socket.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._accept_connections, daemon=True)
        self._thread.start()
        logger.info(f"Test Honeypot started and listening on port {self.port}")

    def _accept_connections(self):
        while self._running:
            try:
                client_socket, addr = self._server_socket.accept()
                client_socket.settimeout(3)
                logger.info(f"Connection accepted from {addr}")
                session = self._action.connect({"client_ip": addr[0]})
                with client_socket:
                    while self._running:
                        data = client_socket.recv(1024)
                        if not data:
                            break
                        logger.info(f"Received data: {data.decode()}")
                        response = self._action.query(data.decode(), session)
                        client_socket.sendall(response.encode())
            except OSError:
                break

    def stop(self):
        self._running = False
        if self._server_socket:
            self._server_socket.close()
            self._server_socket = None
        if self._thread:
            self._thread.join()
        logger.info("Test Honeypot stopped")


class TestBaseHoneypot:
    def test_base_honeypot(self):
        with pytest.raises(
            TypeError, match="Can't instantiate abstract class BaseHoneypot"
        ):
            BaseHoneypot()

    def test_honeypot(self):
        honeypot = HoneypotTest()
        assert honeypot is not None

        try:
            honeypot.start()
            assert 1024 <= honeypot.port <= 65535
            for i in range(2):  # Two sessions
                data = ["hello", "world"]
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                    client_socket.settimeout(3)
                    client_socket.connect(("0.0.0.0", honeypot.port))
                    for data_input in data:
                        # noinspection PyTypeChecker
                        client_socket.sendall(data_input.encode())
                        response = client_socket.recv(
                            1024,
                        )
                        if data_input == "hello":
                            assert response.decode() == "hello"
                        else:
                            assert response.decode() == "helloworld"
        finally:
            honeypot.stop()


class TestHoneypotUtils:
    def test_allocate_port(self):
        port = allocate_port()
        assert isinstance(port, int)
        assert 1024 <= port <= 65535


class TestInvokeLimiter:
    def test_invoke_limit(self):
        limiter = InvokeLimiter(2, 1)
        for _ in range(2):
            assert limiter.can_invoke("v1")
        for _ in range(2):
            assert not limiter.can_invoke("v1")
        for _ in range(2):
            assert limiter.can_invoke("v2")
        sleep(2)
        for _ in range(2):
            assert limiter.can_invoke("v1")
