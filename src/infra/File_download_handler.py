from datetime import datetime
import os
import requests
from urllib.parse import urlparse

from base_honeypot import HoneypotSession


class FileDownloadHandler:
    def __init__(self, fakefs_handler=None, log_callback=None, download_dir=None):
        if download_dir is None:
            download_dir = os.environ.get(
                "HONEYPOT_DOWNLOAD_DIR", "/honeypot/downloads"
            )
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
            content_bytes = resp.content
            content_str = resp.text

            # Save to FakeFS
            fs = session.get("fs")
            if fs and hasattr(fs, "create_file"):
                fs.create_file(f"/tmp/{filename}", content_str)

            # Save to disk
            self._save_to_host(filename, content_bytes)

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

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            fake_file_size = len(content_bytes)  # size in bytes

            return (
                f"--{now}--  {url}\n"
                f"Resolving {url.split('/')[2]}... done.\r\n"
                f"Connecting to {url.split('/')[2]}|192.0.2.1|:80... connected.\r\n"
                f"HTTP request sent, awaiting response... 200 OK\r\n"
                f"Length: {fake_file_size} [text/plain]\r\n"
                f"Saving to: ‘{filename}’\r\n\n"
                f"{filename}              100%[{fake_file_size}/{fake_file_size}]   1.21K/s   in 0.01s\r\n\n"
                f"{now} (1.21 KB/s) - ‘{filename}’ saved [{fake_file_size}/{fake_file_size}]"
            )

        except Exception as e:
            return f"Download failed: {e}\n"

    def _extract_url(self, command):
        parts = command.split()
        for p in parts:
            if p.startswith("http://") or p.startswith("https://"):
                return p
        return None

    def _save_to_host(self, filename, content):
        download_dir = os.environ.get("HONEYPOT_DOWNLOAD_DIR", self.download_dir)
        os.makedirs(download_dir, exist_ok=True)
        path = os.path.join(download_dir, filename)
        with open(path, "wb") as f:
            f.write(content)
