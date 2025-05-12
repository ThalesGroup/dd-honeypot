import logging
import threading

from flask import Flask, request, session, Request, Response

from base_honeypot import BaseHoneypot
from infra.interfaces import HoneypotAction

logger = logging.getLogger(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)


class HTTPHoneypot(BaseHoneypot):
    def __init__(
        self,
        port: int = None,
        action: HoneypotAction = None,
    ):
        super().__init__(port)
        self.app = Flask(__name__)
        self.app.secret_key = "your_secret_key"  # Change this to a secure key
        self._thread = None
        self._action = action

        @self.app.before_request
        def handle_session():
            if "h_session" not in session:
                h_session = self._action.connect({"client_ip": request.remote_addr})
                session["h_session"] = h_session
                logger.info("New session detected")
                logger.info(f"Session data: {h_session}")
            else:
                h_session = session["h_session"]
                logger.info(f"Existing session. Id: {h_session['session_id']}")

        def get_resource_type(r: Request):
            xrw = r.headers.get("X-Requested-With", "").lower()
            accept = r.headers.get("Accept", "").lower()

            if xrw == "xmlhttprequest":
                return "xhr"
            elif xrw == "fetch":
                return "fetch"
            elif "application/json" in accept:
                return "fetch"
            elif "text/html" in accept:
                return "document"
            else:
                return "unknown"

        @self.app.route(
            "/",
            defaults={"path": ""},
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        )
        @self.app.route(
            "/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        )
        def catch_all(path):
            resource_type = get_resource_type(request)
            if resource_type not in ["document", "xhr", "fetch"]:
                return not_found_error(None)

            try:
                result = self._action.request(
                    {"request": request, "path": path, "resource_type": resource_type},
                    session.get("h_session"),
                )
                return Response(result, 200)
            except Exception as e:
                logger.error(f"Error while handling request for path: {path} - {e}", e)
                return Response("Internal Server Error", 500)

        @self.app.errorhandler(404)
        def not_found_error(error):
            logger.warning(f"404 error: Path not found: {request.path}")
            return Response("Not Found", 404)

        @self.app.errorhandler(500)
        def internal_server_error(error):
            logger.error(f"500 error: {error}")
            return Response("Internal Server Error", 500)

    def start(self):
        logger.info(f"Starting honeypot on port {self.port}")

        def run_app():
            self.app.run(
                host="0.0.0.0", port=self.port, debug=False, use_reloader=False
            )

        self._thread = threading.Thread(target=run_app, daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        logger.info(f"Stopping honeypot on port {self.port}")
