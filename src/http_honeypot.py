import logging
import threading

from flask import Flask, request, session, Request, Response

from base_honeypot import BaseHoneypot
from infra.interfaces import HoneypotAction
from werkzeug.serving import make_server

logger = logging.getLogger(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)


class HTTPHoneypot(BaseHoneypot):
    def __init__(
        self,
        port: int = None,
        action: HoneypotAction = None,
        config: dict = None,
    ):
        super().__init__(port, config)
        self.app = Flask(__name__)
        self.app.secret_key = "your_secret_key"
        self._thread = None
        self._server = None
        self._action = action

        @self.app.before_request
        def handle_session():
            if "h_session" not in session:
                h_session = self._action.connect({"client_ip": request.remote_addr})
                session["h_session"] = h_session
                logger.info(f"New session detected: {h_session}")

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
                data = {
                    "host": request.host,
                    "port": (
                        80
                        if ":" not in request.host
                        else int(request.host.split(":")[1])
                    ),
                    "path": path,
                    "args": request.args.to_dict(),
                    "method": request.method,
                    "body": request.get_data(as_text=True),
                    "headers": dict(request.headers),
                    "resource_type": resource_type,
                }
                self.log_data(
                    session["h_session"],
                    {
                        "http-request": data,
                    },
                )
                result = self._action.request(
                    data,
                    session.get("h_session"),
                )
                return Response(result["output"], 200)
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

    def honeypot_type(self) -> str:
        return "http"

    def start(self):
        logger.info(f"Starting honeypot on port {self.port}")

        self._server = make_server("0.0.0.0", self.port, self.app)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        logger.info(f"Stopping honeypot on port {self.port}")
