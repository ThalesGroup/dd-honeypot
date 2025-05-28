import logging

from base_honeypot import HoneypotSession


class ChainedDataHandler:
    def __init__(self, fakefs_handler, llm_handler, log_callback=None):
        self.fakefs_handler = fakefs_handler
        self.llm_handler = llm_handler
        self.log_callback = log_callback

    def connect(self, auth_info: dict) -> HoneypotSession:
        return self.fakefs_handler.connect(auth_info)

    def query(self, command: str, session: HoneypotSession, **kwargs) -> str:
        try:
            result = self.fakefs_handler.query(command, session, **kwargs)
            if result:  # Only fallback if FakeFS couldn't handle
                if command.startswith("wget ") and self.log_callback:
                    # Crude extraction of the URL
                    url = command.split(" ", 1)[1]
                    filename = url.split("/")[-1] if "/" in url else url

                    self.log_callback(
                        session,
                        {
                            "method": "shell",
                            "command": command,
                            "event": "file_download",
                            "url": url,
                            "filename": filename,
                        },
                    )
                return result
        except Exception as e:
            logging.warning(f"FakeFS failed: {e}")
        return self.llm_handler.query(command, session, **kwargs)
