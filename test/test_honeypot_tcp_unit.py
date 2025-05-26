import json
import logging
import os
import socket
import tempfile
import threading
from time import sleep
from typing import Generator

import pytest

from base_honeypot import HoneypotSession, BaseHoneypot
from honeypot_main import start_dd_honeypot
from honeypot_utils import allocate_port
from infra.interfaces import HoneypotAction
from tcp_honeypot import TCPHoneypot

logger = logging.getLogger(__name__)


@pytest.fixture
def tcp_honeypot() -> Generator[BaseHoneypot, None, None]:

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

    honeypot = TCPHoneypot(
        action=BufferSessionDataAction(), config={"name": "TestTcpHoneypot"}
    )
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


def test_tcp_honeypot(tcp_honeypot):
    for i in range(2):  # Two sessions
        data = ["hello", "world"]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(3)
            client_socket.connect(("0.0.0.0", tcp_honeypot.port))
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


def test_tcp_honeypot_main(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("STOP_HONEYPOT", "false")
    port = allocate_port()
    with tempfile.TemporaryDirectory() as tmpdir:
        json.dump(
            {
                "port": port,
                "name": "TestTCPHoneypot",
                "type": "tcp",
                "model_id": "some model",
                "system_prompt": ["You are a test TCP honeypot"],
            },
            open(os.path.join(tmpdir, "config.json"), "w"),
        )
        t = threading.Thread(
            target=start_dd_honeypot,
            args=[tmpdir],
            daemon=True,
        )
        t.start()
        sleep(2)
        try:
            monkeypatch.setattr(
                "infra.data_handler.invoke_llm", lambda *a, **kw: "mocked response"
            )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                input_data = "hello"
                client_socket.settimeout(3)
                client_socket.connect(("0.0.0.0", port))
                # noinspection PyTypeChecker
                client_socket.sendall(input_data.encode())
                response = client_socket.recv(
                    1024,
                )
                assert response.decode() == "mocked response"

        finally:
            monkeypatch.setenv("STOP_HONEYPOT", "true")
            t.join(timeout=5)
