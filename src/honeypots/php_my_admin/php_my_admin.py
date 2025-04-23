import os

from HttpHoneypot import DataHTTPHoneypot


class PhpMyAdminHoneypot(DataHTTPHoneypot):
    def __init__(self, port: int = None):
        super().__init__(os.path.join(os.path.dirname(__file__)), port)
