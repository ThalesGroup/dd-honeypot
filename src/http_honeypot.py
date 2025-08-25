import json
import logging
import threading

from flask import Flask, request, session, Request, Response, make_response, jsonify

from base_honeypot import BaseHoneypot
from infra.interfaces import HoneypotAction
from werkzeug.serving import make_server

logger = logging.getLogger(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

HTTP_SESSIONS = {}


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
        def get_http_dispatcher(path: str):
            """
            Turn the flask Request → `info` dict → action.request(...) →
            flask Response.  All tests exercise only GET; POST and HEAD
            are added for completeness.
            """
            try:
                info = {
                    "method": request.method,
                    "path": path,
                    "args": request.args.to_dict(),
                    "headers": dict(request.headers),
                    "body": request.get_data(as_text=True),
                    "client_ip": request.remote_addr,
                    "resource_type": get_resource_type(request),
                }

                result = self.action.request(info, session["h_session"])

                if not isinstance(result, dict) or "output" not in result:
                    raise ValueError("action.request must return {'output': ...}")

                body = result["output"]
                status = result.get("status", 200)

                if is_json(body):
                    resp = make_response(jsonify(json.loads(body)), status)
                    resp.headers["Content-Type"] = "application/json"
                else:
                    resp = make_response(body, status)
                    resp.headers["Content-Type"] = "text/html; charset=utf-8"

                return resp

            except Exception as exc:
                if isinstance(exc, FileNotFoundError):
                    return "Not Found", 404
                logging.error(f"Error handling request for {path}: {exc}")
                return "Internal Server Error", 500

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

                sid = (
                    str(session["h_session"].id)
                    if "h_session" in session
                    else request.remote_addr
                )
                disp = get_http_dispatcher()
                if sid not in HTTP_SESSIONS:
                    handler = disp.route(
                        sid, path
                    )  # 'path' comes from your request data
                    HTTP_SESSIONS[sid] = {"handler": handler}
                handler = HTTP_SESSIONS[sid]["handler"]
                result = handler.action.request(data, session["h_session"])
                return text_to_response(result["output"])
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


def text_to_response(text: str) -> Response:
    if is_json(text):
        return Response(text, mimetype="application/json")
    else:
        return Response(text)


def is_json(text: str) -> bool:
    n = len(text)
    i, j = 0, n - 1

    while i < n and text[i].isspace():
        i += 1
    while j >= 0 and text[j].isspace():
        j -= 1

    return i < j and (
        (text[i] == "{" and text[j] == "}") or (text[i] == "[" and text[j] == "]")
    )
