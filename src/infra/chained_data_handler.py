import logging

from base_honeypot import HoneypotSession
from infra.interfaces import HoneypotAction


class ChainedDataHandler:
    def __init__(self, fakefs_handler, llm_handler):
        self.fakefs_handler = fakefs_handler
        self.llm_handler = llm_handler

    def connect(self, auth_info: dict) -> HoneypotSession:
        return self.fakefs_handler.connect(auth_info)

    def query(self, command: str, session: HoneypotSession, **kwargs) -> str:
        try:
            result = self.fakefs_handler.query(command, session, **kwargs)
            if result:  # Only fallback if FakeFS couldn't handle
                return result
        except Exception as e:
            logging.warning(f"FakeFS failed: {e}")
        return self.llm_handler.query(command, session, **kwargs)
