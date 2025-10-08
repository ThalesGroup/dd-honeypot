import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


# Utility: tiny session store (in-memory); replace with SQLite if desired
class _SessionMap:
    def __init__(self):
        self._map = {}  # session_id -> backend_name
        self._ts = {}  # session_id -> last_seen
        self._lock = threading.Lock()

    def get(self, sid):
        with self._lock:
            return self._map.get(sid)

    def set(self, sid, backend):
        with self._lock:
            self._map[sid] = backend
            self._ts[sid] = time.time()

    def touch(self, sid):
        with self._lock:
            if sid in self._ts:
                self._ts[sid] = time.time()


SESSION = _SessionMap()


class InProcessDispatcher(BaseHTTPRequestHandler):
    # Configured by start_dispatcher
    ROUTES = []
    BACKENDS = (
        {}
    )  # {"php_my_admin": handler_callable, "boa_server_http": handler_callable}
    MODEL_ID = None
    SYSTEM_PROMPT = ""
    COOKIE_NAME = "hp_session"

    def log_message(self, fmt, *args):
        return

    def _get_or_create_session(self):
        sid = None
        cookie_hdr = self.headers.get("Cookie", "")
        if cookie_hdr:
            parts = [c.strip() for c in cookie_hdr.split(";")]
            for p in parts:
                if p.startswith(self.COOKIE_NAME + "="):
                    sid = p.split("=", 1)[1].strip()
                    break
        if not sid:
            sid = uuid.uuid4().hex
            # set cookie on response (will add again on send)
            self._pending_cookie = f"{self.COOKIE_NAME}={sid}; Path=/; HttpOnly"
        else:
            self._pending_cookie = None
        SESSION.touch(sid)
        return sid

    def _sticky_backend_for(self, path, sid):
        chosen = SESSION.get(sid)
        if chosen in self.BACKENDS:
            return chosen

        for r in self.ROUTES:
            rp = r.get("path", "/")
            if rp == "/" or path == rp or path.startswith(rp + "/"):
                name = r.get("name")
                if name and name != "UNKNOWN" and name in self.BACKENDS:
                    SESSION.set(sid, name)
                    return name

        import random

        if self.BACKENDS:
            name = random.choice(list(self.BACKENDS))
            SESSION.set(sid, name)
            return name
        return None

    def _request_dict(self, method):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        try:
            body_text = body.decode("utf-8", errors="ignore")
        except OSError:
            body_text = ""

        return {
            "method": method,
            "path": self.path,
            "path_only": parsed.path,
            "query": parse_qs(parsed.query),
            "headers": dict(self.headers),
            "cookies": self.headers.get("Cookie", ""),
            "client_ip": self.client_address[0],
            "body": body_text,
            "raw_body": body,
        }

    def _respond(self, status, headers, body):
        self.send_response(status or 200)
        if getattr(self, "_pending_cookie", None):
            self.send_header("Set-Cookie", self._pending_cookie)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body is None:
            body = b""
        if isinstance(body, str):
            body = body.encode("utf-8", errors="ignore")
        self.wfile.write(body)

    def _handle_method(self, method):
        sid = self._get_or_create_session()
        req = self._request_dict(method)
        backend = self._sticky_backend_for(req["path_only"], sid)

        if not backend or backend not in self.BACKENDS:
            return self._respond(404, {"Content-Type": "text/plain"}, "Not found")

        # Call the backend handler (in-process)
        # Contract: handler(req_dict) -> (status:int, headers:dict, body:str|bytes)
        try:
            status, headers, body = self.BACKENDS[backend](req)
        except Exception as e:
            return self._respond(
                500, {"Content-Type": "text/plain"}, f"backend error: {e}"
            )

        return self._respond(status, headers, body)

    def do_GET(self):
        return self._handle_method("GET")

    def do_POST(self):
        return self._handle_method("POST")


def start_dispatcher(port, routes, backends, model_id=None, system_prompt=None):
    """
    routes: list[dict], e.g. [{"path": "/phpmyadmin", "name": "php_my_admin"}, ...]
    backends: dict[str, callable], name -> handler(req) => (status, headers, body)
    """
    InProcessDispatcher.ROUTES = routes or []
    InProcessDispatcher.BACKENDS = backends or {}
    InProcessDispatcher.MODEL_ID = model_id
    InProcessDispatcher.SYSTEM_PROMPT = "\n".join(system_prompt or [])

    httpd = HTTPServer(("0.0.0.0", int(port)), InProcessDispatcher)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd
