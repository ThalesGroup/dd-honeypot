import logging

from base_honeypot import HoneypotSession


class ChainedDataHandler:
    def __init__(self, handlers):
        self.handlers = handlers  # List of handler instances

    def connect(self, auth_info: dict) -> HoneypotSession:
        session = self.handlers[0].connect(auth_info)
        for handler in self.handlers[1:]:
            if hasattr(handler, "attach_session"):
                handler.attach_session(session)
        return session

    def query(self, command: str, session: HoneypotSession, **kwargs) -> str:
        for handler in self.handlers:
            try:
                result = handler.query(command, session, **kwargs)
                if result:
                    return result
            except Exception as e:
                logging.warning(f"{handler.__class__.__name__} failed: {e}")
        return "Command not handled.\n"
