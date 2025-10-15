import logging
import os
import threading
import uuid
from urllib.parse import urlparse

from flask import Flask, request, session, Request, Response
from werkzeug.serving import make_server

from base_honeypot import BaseHoneypot, HoneypotSession
from infra.interfaces import HoneypotAction

logger = logging.getLogger(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

HTTP_SESSIONS = {}
_COOKIE = "hp_session"


def extract_routing_key(ctx) -> str:
    return (ctx.get("path") or "/").lower()


def extract_meta(ctx) -> dict:
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


def extract_session_id(ctx) -> str:
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
        try:
            from flask import g

            g._hp_pending_cookie = f"{_COOKIE}={sid}; Path=/; HttpOnly"
        except OSError:
            pass
    return sid


def _normalize_backend_name(name: str) -> str:
    """Normalize backend names for robust matching."""
    return name.lower().replace(" ", "_").replace("-", "_").strip()


class HTTPHoneypot(BaseHoneypot):
    def __init__(
        self,
        port: int = None,
        action: HoneypotAction = None,
        config: dict = None,
        dispatcher_routes=None,
        inprocess_backends=None,
    ):
        super().__init__(port, config)
        self.dispatcher_routes = dispatcher_routes
        # Normalize backend keys for robust matching
        self.inprocess_backends = {
            _normalize_backend_name(k): v for k, v in (inprocess_backends or {}).items()
        }
        if "unknown" not in self.inprocess_backends:

            def _unknown_backend(_ctx):
                return 200, {"Content-Type": "text/html"}, "<html>OK</html>"

            self.inprocess_backends["unknown"] = _unknown_backend
        self.set_dispatch_backends(self.inprocess_backends)
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
            print(
                f"CATCH_ALL: is_dispatcher={self.is_dispatcher}, path={request.path}, dispatcher_routes={getattr(self, 'dispatcher_routes', None)}"
            )
            resource_type = get_resource_type(request)

            if self.is_dispatcher:
                try:
                    from flask import g

                    if not self.dispatch_rules:
                        try:
                            self._load_dispatcher_rules()
                        except OSError:
                            pass
                    ctx = _build_ctx_from_request()
                    print(f"CATCH_ALL: calling _dispatch_handle with ctx={ctx}")
                    sid = extract_session_id(ctx)
                    status, headers, body = self._dispatch_handle(ctx)

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
            logger.warning(f"404 error: Path not found: {request.path}")
            return Response("Not Found", 404)

        @self.app.errorhandler(500)
        def internal_server_error(error):
            logger.error(f"500 error: {error}")
            return Response("Internal Server Error", 500)

    def _dispatch_handle(self, ctx):
        """Dispatch the request based on dispatcher rules."""
        logger.info(f"DISPATCH_HANDLE: called with ctx={ctx}")
        path = (ctx.get("path") or "/").lower().rstrip("/")
        if path == "":
            path = "/"
        routes = (
            getattr(self, "dispatcher_routes", None)
            or getattr(self, "dispatch_rules", None)
            or []
        )
        # Sort routes by descending path length to prioritize more specific matches
        routes = sorted(
            routes,
            key=lambda r: len((r.get("path") or "").rstrip("/").lower()),
            reverse=True,
        )
        logger.info(
            f"DISPATCH_HANDLE: available backend keys: {list(getattr(self, 'inprocess_backends', {}).keys())}"
        )
        for route in routes:
            route_path = (route.get("path") or "").lower().rstrip("/")
            if route_path == "":
                route_path = "/"
            logger.info(f"DISPATCH_HANDLE: checking route: {route_path} vs {path}")
            # Only match "/" if the path is exactly "/"; otherwise, match prefix for other routes
            is_root_match = route_path == "/" and path == "/"
            is_prefix_match = route_path != "/" and (
                path == route_path or path.startswith(route_path + "/")
            )
            if is_root_match or is_prefix_match:
                backend_name = (route.get("name") or "").strip()
                norm_backend_name = _normalize_backend_name(backend_name)
                logger.info(
                    f"DISPATCH_HANDLE: looking for backend_name: '{backend_name}' (normalized: '{norm_backend_name}')"
                )
                handler = getattr(self, "inprocess_backends", {}).get(norm_backend_name)
                logger.info(
                    f"DISPATCH_HANDLE: Matched route. Backend name: '{backend_name}', Normalized: '{norm_backend_name}', Handlers: {list(getattr(self, 'inprocess_backends', {}).keys())}, Handler found: {bool(handler)}"
                )
                if handler:
                    return handler(ctx)
                else:
                    logger.warning(
                        f"DISPATCH_HANDLE: No handler found for backend: '{backend_name}' (normalized: '{norm_backend_name}')"
                    )
        logger.warning(f"DISPATCH_HANDLE: No route matched for path: {path}")
        return 404, {"Content-Type": "text/plain"}, "Not found"

    def as_backend_handler(self) -> callable:
        """Return a handler function that can be used as a backend in dispatcher mode."""
        name_norm = _normalize_backend_name(self.name or "")

        def _handle(ctx: dict):
            """Handle incoming request context and return HTTP response."""
            data = {
                "host": (ctx.get("headers") or {}).get("Host", ""),
                "port": 80,
                "path": (ctx.get("path") or "/").lstrip("/"),
                "args": ctx.get("query") or {},
                "method": ctx.get("method") or "GET",
                "body": ctx.get("body") or "",
                "headers": ctx.get("headers") or {},
                "resource_type": "document",
            }
            sid = ctx.get("cookies") or ""
            h_session = {"session_id": sid} if sid else {"session_id": uuid.uuid4().hex}
            self.log_data(HoneypotSession(h_session), {"http-request": data})
            path_lower = (ctx.get("path") or "/").lower()

            if name_norm == "php_my_admin":
                if path_lower.startswith("/phpmyadmin"):
                    return 200, {"Content-Type": "text/html"}, "<html>phpMyAdmin</html>"
                if path_lower.startswith("/dbadmin"):
                    return 200, {"Content-Type": "text/html"}, "<html>phpMyAdmin</html>"
                return (
                    200,
                    {"Content-Type": "text/html"},
                    "<html>phpMyAdmin home</html>",
                )

            if name_norm == "boa_server_http":
                if path_lower.endswith("/login.htm") or path_lower == "/login.htm":
                    return 200, {"Content-Type": "text/html"}, "<html>Boa login</html>"
                return 200, {"Content-Type": "text/html"}, "<html>Boa home</html>"

            return 200, {"Content-Type": "text/html"}, "<html>OK</html>"

        return _handle

    def honeypot_type(self) -> str:
        return "http"

    def start(self):
        logger.info(f"Starting honeypot on port {self.port}")

        if self.is_dispatcher:
            try:
                self._load_dispatcher_rules()
            except OSError:
                logger.error(f"Failed to load dispatcher rules:", exc_info=True)

        self._server = make_server("0.0.0.0", self.port, self.app)

        try:
            actual_port = self._server.server_port
        except OSError:
            actual_port = self.port
        if int(self.port) == 0 and actual_port:
            self.port = actual_port
            if getattr(self, "config_dir", None):
                try:
                    open(os.path.join(self.config_dir, "bound_port"), "w").write(
                        str(self.port)
                    )
                except OSError:
                    pass

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
