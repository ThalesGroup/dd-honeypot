import logging

from base_honeypot import HoneypotSession


class ChainedDataHandler:
    def __init__(self, handlers):
        self.handlers = handlers  # List of handler instances

    def connect(self, auth_info: dict) -> HoneypotSession:
        logging.info(f"ChainedDataHandler.connect: {auth_info}")
        session = self.handlers[0].connect(auth_info)

        if hasattr(session.get("fs"), "fakefs"):
            logging.warning("[ChainedDataHandler.connect] Unwrapping fs from handler")
            session["fs"] = session["fs"].fakefs

        return session

    def query(self, command: str, session: HoneypotSession, **kwargs) -> dict:
        for handler in self.handlers:
            try:
                result = handler.query(command, session, **kwargs)
                if result:
                    return result
            except Exception as e:
                logging.warning(f"{handler.__class__.__name__} failed: {e}")
        return {"output": "Command not handled."}
