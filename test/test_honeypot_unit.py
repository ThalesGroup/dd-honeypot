import logging
import pytest

from src.base_honeypot import BaseHoneypot, HoneypotSession
from src.honeypot_utils import allocate_port



logger = logging.getLogger(__name__)

class HoneypotTest(BaseHoneypot):
    def start(self):
        logger.info(f"Test Honeypot started on port {self.port}")

    def stop(self):
        logger.info("Test Honeypot stopped")

    def query(self, query: str, session: HoneypotSession, **kwargs) -> list:
        logger.info(f"Query received in session {session.session_id}: {query}")
        return ["result"]

class TestBaseHoneypot:
    def test_base_honeypot(self):
        with pytest.raises(TypeError, match="Can't instantiate abstract class BaseHoneypot"):
            BaseHoneypot()

    def test_honeypot(self):
        honeypot = HoneypotTest()
        assert honeypot is not None

        try:
            honeypot.start()
            assert 1024 <= honeypot.port <= 65535
            session = honeypot.connect({})
            assert session is not None
            assert honeypot.query("test query", session) == ["result"]
        finally:
            honeypot.stop()


class TestHoneypotUtils:
    def test_allocate_port(self):
        port = allocate_port()
        assert isinstance(port, int)
        assert 1024 <= port <= 65535
