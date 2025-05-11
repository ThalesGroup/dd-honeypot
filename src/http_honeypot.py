import json
import os.path
from typing import Callable, List

from flask import Flask, request, session, Request, Response
from base_honeypot import BaseHoneypot, HoneypotSession
import threading
import logging

from llm_utils import invoke_llm

logger = logging.getLogger(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)


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
            try:
                # Call the request callback (logging request details)
                return self._request_callback(path, request)
            except Exception as e:
                logger.error(f"Error while handling request for path: {path} - {e}")
                return Response("Internal Server Error", 500)

        @self.app.errorhandler(404)
        def not_found_error(error):
            # Handle 404 error for unknown paths
            logger.warning(f"404 error: Path not found: {request.path}")
            return Response("Not Found", 404)

        @self.app.errorhandler(500)
        def internal_server_error(error):
            # Handle 500 error
            logger.error(f"500 error: {error}")
            return Response("Internal Server Error", 500)

    def start(self):
        def run_app():
            self.app.run(
                host="127.0.0.1", port=self.port, debug=False, use_reloader=False
            )

        self.thread = threading.Thread(target=run_app)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)


class DataHTTPHoneypot(HTTPHoneypot):

    def __init__(self, folder: str, port: int = None):
        super().__init__(port, self.http_request)
        self._folder = folder
        self._data: List[dict] = []
        self._configuration = json.load(
            open(os.path.join(folder, "configuration.json"))
        )
        with open(os.path.join(folder, "data.jsonl")) as f:
            for line in f:
                if line.strip() != "":
                    self._data.append(json.loads(line))

    @staticmethod
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

    @staticmethod
    def base_system_prompt() -> List[str]:
        return [
            "You should only respond with the content of the file requested, and nothing else",
            "Do not include any additional information or context",
            "If the file does not exist, return a 404 error message",
            "When you return an html include the most important parts actionable parts like forms, buttons, links, do not include images, javascript or other references",
            "The name, ids and titles MUST MATCH the original ones",
            "Login should always succeed",
        ]

    def system_prompt(self) -> str:
        result = "\n".join(self._configuration["system-prompt"])
        result += "\n".join(self.base_system_prompt())
        return result

    def model_id(self) -> str:
        return self._configuration.get("model-id", "anthropic.claude-instant-v1")

    def http_request(self, path: str, r: Request) -> Response:
        for line in self._data:
            if line["path"] == path and r.args == line["args"]:
                return Response(line["content"], 200)
        resource_type = self.get_resource_type(r)
        if resource_type in ["document", "xhr", "fetch"]:
            user_prompt = f"""Method: {r.method}
    path: {path}
    args: {dict(r.args)}
    resource_type: {resource_type}
    Headers: {dict(r.headers)}
    Body: {r.get_data() if r.get_data() else 'No body'}"""

            response_text = invoke_llm(
                self.system_prompt(), user_prompt, self.model_id()
            )
            self._data.append({"path": path, "args": r.args, "content": response_text})
            self.stop()
            return Response(response_text, 200)
        return Response("Not Found", 404)

    def stop(self):
        with open(os.path.join(self._folder, "data.jsonl"), "w") as f:
            for line in self._data:
                f.write(json.dumps(line) + "\n")
