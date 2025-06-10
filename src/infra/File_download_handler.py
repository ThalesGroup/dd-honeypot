import os
import requests
from urllib.parse import urlparse

from base_honeypot import HoneypotSession


class FileDownloadHandler:
    def __init__(
        self, fakefs_handler=None, log_callback=None, download_dir="/honeypot/downloads"
    ):
        self.fakefs_handler = fakefs_handler
        self.log_callback = log_callback
        self.download_dir = download_dir

    def connect(self, auth_info: dict) -> HoneypotSession:
        # Delegate session creation to FakeFS (or create your own if needed)
        return self.fakefs_handler.connect(auth_info)

    def query(self, command, session, **kwargs):
        if not (command.startswith("wget ") or command.startswith("curl ")):
            return None

        url = self._extract_url(command)
        if not url:
            return "Invalid URL\n"

        filename = os.path.basename(urlparse(url).path) or "index.html"
        try:
            resp = requests.get(url, timeout=3)
            content = resp.text

            # Save to FakeFS
            if self.fakefs_handler:
                self.fakefs_handler.create_file(session, filename, content)

            # Save to disk
            self._save_to_host(filename, content)

            # Log
            if self.log_callback:
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

            return f"Downloaded {filename}\n"

        except Exception as e:
            return f"Download failed: {e}\n"

    def _extract_url(self, command):
        parts = command.split()
        for p in parts:
            if p.startswith("http://") or p.startswith("https://"):
                return p
        return None

    def _save_to_host(self, filename, content):
        os.makedirs(self.download_dir, exist_ok=True)
        path = os.path.join(self.download_dir, filename)
        with open(path, "w") as f:
            f.write(content)
