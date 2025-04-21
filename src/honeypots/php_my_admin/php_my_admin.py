import json
import os
from typing import List

from flask import Request, Response

from HttpHoneypot import HTTPHoneypot


class PhpMyAdminHoneypot(HTTPHoneypot):

    def __init__(self, port: int = None):
        super().__init__(port, self.http_request)
        self._data: List[dict] = []
        with open(os.path.join(os.path.dirname(__file__), "data.jsonl")) as f:
            for line in f:
                self._data.append(json.loads(line))

    def http_request(self, path: str, r: Request) -> Response:
        for line in self._data:
            if line["path"] == path:
                return Response(line["content"], 200)
        return Response("Not Found", 404)
