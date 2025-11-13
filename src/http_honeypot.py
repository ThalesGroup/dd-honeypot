import logging
import threading
import uuid
from urllib.parse import urlparse

from flask import Flask, request, session, Request, Response, g
from werkzeug.serving import make_server

from base_honeypot import BaseHoneypot, HoneypotSession
from infra.interfaces import HoneypotAction

logger = logging.getLogger(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

_COOKIE = "hp_session"


def _extract_meta(ctx: dict) -> dict:
    headers = ctx.get("headers") or {}
    return {
        "method": ctx.get("method"),
        "client_ip": ctx.get("client_ip"),
        "headers": {
            k: v
            for k, v in headers.items()
            if k.lower() in ("user-agent", "accept", "x-requested-with")
        },
        "query": ctx.get("query") or {},
    }


def _extract_session_id(ctx: dict) -> str:
    cookies = ctx.get("cookies") or ""
    sid = None
    if cookies:
        for part in cookies.split(";"):
            p = part.strip()
            if p.startswith(_COOKIE + "="):
                sid = p.split("=", 1)[1].strip()
                break
    if not sid:
        sid = uuid.uuid4().hex
        g._hp_pending_cookie = f"{_COOKIE}={sid}; Path=/; HttpOnly"
    return sid


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
                self.log_login(h_session, {"client_ip": request.remote_addr})

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
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    f"CATCH_ALL: is_dispatcher={self.is_dispatcher}, path={request.path}, dispatcher_routes={getattr(self, 'dispatcher_routes', None)}"
                )
            resource_type = get_resource_type(request)

            if self.is_dispatcher:
                try:
                    from flask import g

                    ctx = _build_ctx_from_request()
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"CATCH_ALL: calling dispatch with ctx={ctx}")
                    sid = _extract_session_id(ctx)
                    ctx["session_id"] = sid
                    ctx["routing_key"] = (ctx.get("path") or "/").lower()
                    ctx["meta"] = _extract_meta(ctx)
                    status, headers, body = self.dispatch(ctx)

                    pending = getattr(g, "_hp_pending_cookie", None)
                    resp = Response(
                        body if isinstance(body, (bytes, bytearray)) else str(body),
                        status or 200,
                    )
                    for k, v in (headers or {}).items():
                        resp.headers[k] = v
                    if pending:
                        try:
                            cookie_value = pending.split("=", 1)[1].split(";", 1)[0]
                            resp.set_cookie(
                                _COOKIE, cookie_value, path="/", httponly=True
                            )
                        except OSError:
                            resp.headers["Set-Cookie"] = pending
                    # Log dispatcher
                    self.log_data(
                        HoneypotSession({"session_id": sid}),
                        {
                            "type": "Dispatcher",
                            "name": self.name or "HTTP Dispatcher",
                            "method": ctx.get("method", "UNKNOWN"),
                            "command": ctx.get("path", "UNKNOWN"),
                        },
                    )
                    return resp
                except Exception as e:
                    logger.error(
                        f"Dispatcher error for path {path}: {e}", exc_info=True
                    )
                    return Response("Internal Server Error", 500)

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
                return text_to_response(result["output"])
            except Exception as e:
                logger.error(
                    f"Error while handling request for path: {path} - {e}",
                    exc_info=True,
                )
                return Response("Internal Server Error", 500)

        def _build_ctx_from_request() -> dict:
            """Convert Flask request to context dictionary."""
            raw = request.path or "/"
            parsed = urlparse(raw)
            try:
                body_text = request.get_data(as_text=True)
            except OSError:
                body_text = ""
            return {
                "method": request.method,
                "path": parsed.path,
                "raw_path": request.full_path or request.path,
                "query": request.args.to_dict(flat=False),
                "headers": dict(request.headers),
                "cookies": request.headers.get("Cookie", ""),
                "client_ip": request.remote_addr,
                "body": body_text,
            }

        @self.app.errorhandler(404)
        def not_found_error(error):
            logger.warning(f"404 error: Path not found: {request.path} ({error})")
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
        logger.info(
            f"HTTP honeypot listening on port {self.port} (dispatcher={self.is_dispatcher})"
        )

    def stop(self):
        if self._server:
            self._server.shutdown()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        logger.info(f"Stopping honeypot on port {self.port}")

    def handle_request(self, ctx: dict) -> tuple:
        # Delegate to self._action.request for static/data-driven responses
        if self._action and hasattr(self._action, "request"):
            try:
                req = {
                    "method": ctx.get("method", "GET"),
                    "path": ctx.get("path", ""),
                    "args": ctx.get("query", {}),
                    "body": ctx.get("body", ""),
                    "headers": ctx.get("headers", {}),
                    "resource_type": ctx.get("resource_type", "document"),
                }
                s = HoneypotSession({"session_id": ctx.get("session_id")})
                result = self._action.request(req, s)
                logger.debug(f"handle_request: req={req} result={result}")
                output = result.get("output") if isinstance(result, dict) else result
                if output:
                    return 200, {"Content-Type": "text/html"}, output
            except Exception as e:
                logger.error(f"Error in action.request: {e}")
        # Fallback to generic response
        self.log_data(
            HoneypotSession({"session_id": ctx.get("session_id")}),
            {"http-request": ctx},
        )
        return 200, {"Content-Type": "text/html"}, "<html>OK</html>"


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
