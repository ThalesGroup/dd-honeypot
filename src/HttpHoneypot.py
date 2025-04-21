from typing import Callable

from flask import Flask, request, session, Request, Response
from base_honeypot import BaseHoneypot, HoneypotSession
import threading
import logging


logger = logging.getLogger(__name__)


def http_honeypot_request(path: str, r: Request) -> Response:
    logger.info(f"Received request: {path} {r.method} {r.url}")
    logger.info(f"Headers: {dict(r.headers)}")
    logger.info(f"Body: {r.data.decode('utf-8') if r.data else 'No body'}")
    return Response("Request logged", 200)


class HTTPHoneypot(BaseHoneypot):
    def __init__(
        self,
        port: int = None,
        request_callback: Callable[[str, Request], Response] = http_honeypot_request,
    ):
        super().__init__(port)
        self.app = Flask(__name__)
        self.app.secret_key = "your_secret_key"  # Change this to a secure key
        self.thread = None
        self._request_callback = request_callback

        @self.app.before_request
        def handle_session():
            if "h_session" not in session:
                h_session = HoneypotSession()
                h_session["client_ip"] = request.remote_addr
                session["h_session"] = h_session

                logger.info("New session detected")
                logger.info(f"Session data: {dict(session)}")
            else:
                h_session = session["h_session"]
                logger.info(f"Existing session. Id: {h_session['session_id']}")

        @self.app.route(
            "/",
            defaults={"path": ""},
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        )
        @self.app.route(
            "/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        )
        def catch_all(path):
            return self._request_callback(path, request)

    def start(self):
        def run_app():
            self.app.run(
                host="0.0.0.0", port=self.port, debug=False, use_reloader=False
            )

        self.thread = threading.Thread(target=run_app)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
