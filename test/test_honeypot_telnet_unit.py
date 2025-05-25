import logging
import logging
import telnetlib
from typing import Generator

import pytest

from base_honeypot import HoneypotSession
from infra.interfaces import HoneypotAction
from telnet_honeypot import TelnetHoneypot

logger = logging.getLogger(__name__)


@pytest.fixture
def telnet_honeypot() -> Generator[TelnetHoneypot, None, None]:

    class TelnetAction(HoneypotAction):
        def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
            return "Response to: " + query

    honeypot = TelnetHoneypot(action=TelnetAction(), name="TestTelnetHoneypot")
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


def test_telnet_honeypot(telnet_honeypot):
    with telnetlib.Telnet("0.0.0.0", telnet_honeypot.port, timeout=5) as tn:
        tn.read_until(b"Login: ")
        tn.write(b"admin\n")

        tn.read_until(b"Password: ")
        tn.write(b"123456\n")

        tn.read_until(b"> ").decode()
        tn.write(b"exit\n")
        output = tn.read_all().decode()
        assert "Goodbye" in output
