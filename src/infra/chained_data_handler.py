import logging

from base_honeypot import HoneypotSession


class ChainedDataHandler:
    def __init__(self, handlers):
        self.handlers = handlers  # List of handler instances

    def connect(self, auth_info: dict) -> HoneypotSession:
        # Assume all handlers use the same session model — delegate to first
        return self.handlers[0].connect(auth_info)

    def query(self, command: str, session: HoneypotSession, **kwargs) -> str:
        for handler in self.handlers:
            try:
                result = handler.query(command, session, **kwargs)
                if result:
                    return result
            except Exception as e:
                logging.warning(f"{handler.__class__.__name__} failed: {e}")
        return "Command not handled.\n"
