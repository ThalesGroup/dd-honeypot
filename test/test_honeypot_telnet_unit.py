import logging
import telnetlib
import time
from typing import Generator

import pytest

from base_honeypot import HoneypotSession
from infra.interfaces import HoneypotAction
from telnet_honeypot import TelnetHoneypot

logger = logging.getLogger(__name__)


@pytest.fixture
def telnet_honeypot(tmp_path) -> Generator[TelnetHoneypot, None, None]:

    class TelnetAction(HoneypotAction):
        def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
            return "Response to: " + query

    honeypot = TelnetHoneypot(
        action=TelnetAction(),
        config={
            "name": "TestTelnetHoneypot",
            "telnet": {
                "banner": "Welcome to TestTelnetHoneypot",
                "login-prompt": "Login: ",
                "password-prompt": "Password: ",
            },
            "data_dir": str(tmp_path),
        },
    )
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


def test_telnet_honeypot(telnet_honeypot):
    with telnetlib.Telnet("0.0.0.0", telnet_honeypot.port, timeout=3) as tn:
        tn.expect([b"Login: "], timeout=2)
        tn.write(b"admin\n")

        tn.expect([b"Password: "], timeout=2)
        tn.write(b"123456\n")

        tn.expect([b"# "], timeout=2)
        for i in range(5):
            command = f"command_{i}\n"
            tn.write(command.encode())
            tn.expect([b"# "], timeout=2)
        tn.write(b"exit\n")
        output = tn.read_all().decode()
        assert "Goodbye" in output


def test_telnet_multiple_sessions_short_timeout(telnet_honeypot, monkeypatch):
    monkeypatch.setattr(telnet_honeypot, "SESSION_TIMEOUT", 1)
    logged_data = []

    def fake_log_data(session: HoneypotSession, data: dict):
        logged_data.append({"session_id": session["session_id"], "data": data})

    monkeypatch.setattr(telnet_honeypot, "log_data", fake_log_data)
    _send_commands(telnet_honeypot.port, sleep_between=2)

    assert len(logged_data) == 4
    assert logged_data[0]["session_id"] == logged_data[1]["session_id"]
    assert logged_data[2]["session_id"] == logged_data[3]["session_id"]
    assert logged_data[0]["session_id"] != logged_data[2]["session_id"]


def test_telnet_multiple_sessions_long_timeout(telnet_honeypot, monkeypatch):

    logged_data = []

    def fake_log_data(session: HoneypotSession, data: dict):
        logged_data.append({"session_id": session["session_id"], "data": data})

    monkeypatch.setattr(telnet_honeypot, "log_data", fake_log_data)
    _send_commands(telnet_honeypot.port, sleep_between=1)

    assert len(logged_data) == 3
    assert (
        logged_data[0]["session_id"]
        == logged_data[1]["session_id"]
        == logged_data[2]["session_id"]
    )


def _send_commands(port: int, sleep_between: int):
    for i in range(2):
        with telnetlib.Telnet("0.0.0.0", port, timeout=3) as tn:
            tn.expect([b"Login: "], timeout=2)
            tn.write(b"admin\n")

            tn.expect([b"Password: "], timeout=2)
            tn.write(b"123456\n")

            tn.write(f"command_session{i}\n".encode())
            tn.expect([b"# "], timeout=2)
        time.sleep(sleep_between)
