import json
import os.path
import tempfile
import threading
import time
from typing import Generator
from unittest.mock import patch

import pytest
import requests

from base_honeypot import HoneypotSession, BaseHoneypot
from conftest import get_config, get_honeypots_folder
from honeypot_main import start_dd_honeypot
from honeypot_utils import init_env_from_file, allocate_port
from http_honeypot import HTTPHoneypot, is_json
from infra.honeypot_wrapper import create_honeypot
from infra.interfaces import HoneypotAction


def wait_for_server(port: int, retries=5, delay=1):
    for _ in range(retries):
        try:
            requests.get(f"http://127.0.0.1:{port}")
            return True
        except requests.ConnectionError:
            time.sleep(delay)
    raise RuntimeError(f"Server on port {port} did not start after {retries} retries")


@pytest.fixture
def http_honeypot() -> Generator[HTTPHoneypot, None, None]:
    class TestHTTPDataHandler(HoneypotAction):
        def request(self, info: dict, session: HoneypotSession, **kwargs) -> dict:
            if info["path"] == "json_path":
                return {"output": '{"message": "Request logged"}'}
            else:
                return {"output": "Request logged"}

    with patch("infra.data_handler.invoke_llm", return_value="Request logged"):
        honeypot = HTTPHoneypot(
            action=TestHTTPDataHandler(), config={"name": "TestHTTPHoneypot"}
        )
        honeypot.session = HoneypotSession()
        try:
            honeypot.start()
            wait_for_server(honeypot.port)
            yield honeypot
        finally:
            honeypot.stop()


@pytest.fixture
def php_my_admin() -> Generator[BaseHoneypot, None, None]:
    config = get_config("php_my_admin")
    config["data_file"] = os.path.join(
        get_honeypots_folder(), "php_my_admin", "data.jsonl"
    )
    config["port"] = allocate_port()

    class TestPHPAction(HoneypotAction):
        def request(self, info: dict, session: HoneypotSession, **kwargs) -> dict:
            if info.get("path") == "path":
                raise FileNotFoundError("Not Found")
            return {"output": "Default content"}

    honeypot = create_honeypot(config)
    honeypot._action = TestPHPAction()
    honeypot.session = HoneypotSession()
    try:
        honeypot.start()
        wait_for_server(honeypot.port)
        yield honeypot
    finally:
        honeypot.stop()


def test_basic_http_request(http_honeypot):
    response = requests.get(
        f"http://0.0.0.0:{http_honeypot.port}/path", headers={"Accept": "text/html"}
    )
    assert response.status_code == 200
    assert "Request logged" in response.text
    assert response.headers["Content-Type"] == "text/html; charset=utf-8"


def test_json_response(http_honeypot):
    response = requests.get(
        f"http://0.0.0.0:{http_honeypot.port}/json_path",
        headers={"Accept": "text/html"},
    )
    assert response.status_code == 200
    assert "Request logged" in response.text
    assert response.json()["message"] == "Request logged"
    assert response.headers["Content-Type"] == "application/json"


def test_php_my_admin(php_my_admin):
    requests.get(f"http://0.0.0.0:{php_my_admin.port}/path")
    response = requests.get(f"http://0.0.0.0:{php_my_admin.port}/path")
    assert response.status_code == 404
    assert "Not Found" in response.text


@pytest.mark.skip(reason="Playwright is not installed in the CI environment")
def test_webdriver_http_request(php_my_admin):
    init_env_from_file()

    def log_request(request):
        # Filter for types that are usually triggered directly
        if request.resource_type in ["document", "xhr", "fetch"]:
            print(f">> {request.method} {request.url} ({request.resource_type})")
            if request.post_data:
                print(f"POST data: {request.post_data}")

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p, p.chromium.launch(
        headless=False
    ) as browser, browser.new_page() as page:
        page.on("request", log_request)
        page.goto(f"http://127.0.0.1:{php_my_admin.port}")
        page.fill('input[name="pma_username"]', "root")
        page.fill('input[name="pma_password"]', "rootpassword")
        page.click("input#input_go")
        page.wait_for_load_state("networkidle")
        try:
            page.wait_for_selector(
                'a[href*="route=/server/sql"]', state="visible", timeout=2000
            )
            page.click('a[href*="route=/server/sql"]')
            page.wait_for_timeout(1000)
            page.keyboard.type("SELECT 1 AS col")
            page.click("#button_submit_query")
            page.wait_for_selector("table.table_results")
            table_text = page.inner_text("table.table_results")
            print("Table content:")
            print(table_text)
        except TimeoutError:
            error = page.query_selector(".error")
            if error:
                print("❌ Login failed:", error.inner_text())
            else:
                print("❌ Login failed or SQL tab not found.")


def test_http_honeypot_main(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("STOP_HONEYPOT", "false")
    port = allocate_port()
    with tempfile.TemporaryDirectory() as tmpdir:
        json.dump(
            {
                "port": port,
                "name": "TestHTTPHoneypot",
                "type": "http",
                "model_id": "some model",
                "system_prompt": ["You are a test HTTP honeypot"],
            },
            open(os.path.join(tmpdir, "config.json"), "w"),
        )
        t = threading.Thread(
            target=start_dd_honeypot,
            args=[tmpdir],
            daemon=True,
        )
        t.start()
        try:
            assert wait_for_server(port)
            monkeypatch.setattr(
                "infra.data_handler.DataHandler.request",
                lambda *a, **kw: {"output": "mocked response"},
            )
            response = requests.get(
                f"http://0.0.0.0:{port}/some_path", headers={"Accept": "text/html"}
            )
            assert response.status_code == 200
            assert "mocked response" == response.text
        finally:
            monkeypatch.setenv("STOP_HONEYPOT", "true")
            t.join(timeout=5)


@pytest.mark.parametrize(
    "text",
    [
        '{"key": "value"}',
        '   { "a": 1 }   ',
        '\n\t{ "a": 1 }\n',
        "[1, 2, 3]",
        "   [1,2,3]   ",
        "\n\t[1,2,3]\n",
        "{}",
        "[]",
        "   {}   ",
        "\n[]\n",
    ],
)
def test_is_json_true(text):
    assert is_json(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "",
        "plain text",
        "{not json",
        "not json}",
        "[not json",
        "not json]",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
    ],
)
def test_is_json_false(text):
    assert is_json(text) is False


def debug_session(client, url):
    print(f"\nSending request to {url}")
    print(f"Client cookies before request: {client.cookies}")

    resp = client.get(url, allow_redirects=False)

    sid = None
    for cookie in client.cookies:
        if cookie.name == "hp_session":
            sid = cookie.value

    print(f"Response status: {resp.status_code}")
    print(f"Response cookies: {resp.cookies}")
    print(f"Client cookies after request: {client.cookies}")
    print(f"Session ID from cookies: {sid}")
    print(f"Response body: {resp.text[:50]}...")

    return resp


def request(self, info, session):
    result = self._data_store.search(info)
    if result:
        print(f"DataHandler.request: Found cached response for {info}: {result}")
        return {"response": result}

    print(f"DataHandler.request: Making LLM call for {info}")
    invoked, response = self.invoke_llm_with_limit("Test input")
    print(f"DataHandler.request: LLM response: {response}")

    if invoked:
        print(f"DataHandler.request: Storing response in cache: {info} -> {response}")
        self._data_store.store(info, response)

    return {"response": response}


def add_session_logging(honeypot):
    original_dispatch = honeypot.dispatch

    def logged_dispatch(ctx):
        sid = ctx.get("session_id")
        print(f"\nDISPATCH: session_id={sid}")
        print(f"DISPATCH: Current _session_map={getattr(honeypot, '_session_map', {})}")

        pinned = getattr(honeypot, "_session_map", {}).get(sid)
        if pinned:
            print(f"DISPATCH: Found pinned backend {pinned} for session {sid}")

        result = original_dispatch(ctx)

        updated_pinned = getattr(honeypot, "_session_map", {}).get(sid)
        print(f"DISPATCH: Updated _session_map={getattr(honeypot, '_session_map', {})}")
        if updated_pinned != pinned:
            print(f"DISPATCH: Session mapping changed: {pinned} -> {updated_pinned}")

        return result

    honeypot.dispatch = logged_dispatch


def test_dispatcher_session_consistency_and_logging(monkeypatch, capsys):
    """
    Test that the dispatcher chooses a backend once per session and logs in dd-honeypot format.
    """
    import tempfile
    import os
    from infra.data_handler import DataHandler
    import time

    llm_calls = []

    def fake_llm_with_limit(*args, **kwargs):
        llm_calls.append(1)
        return "App_A"

    monkeypatch.setattr("infra.data_handler.invoke_llm", fake_llm_with_limit)

    class TestDataHandler(DataHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._session_backends = {}
            print("TestDataHandler initialized")

        def dispatch(self, query_input, session):
            session_id = session.get("session_id")
            print(f"TestDataHandler.dispatch called with session_id: {session_id}")
            print(f"Current session_backends: {self._session_backends}")

            if session_id and session_id in self._session_backends:
                backend = self._session_backends[session_id]
                print(f"Using cached backend {backend} for session {session_id}")
                return backend

            info = {
                "command": "dispatcher-route",
                "path": query_input.get("routing_key", "/"),
            }

            cached = self._data_store.search(info)
            if cached:
                print(f"Found cached dispatch result: {cached}")

            result = self.request(info, session)
            backend_choice = result.get("output", "UNKNOWN")

            if session_id:
                print(f"Storing backend {backend_choice} for session {session_id}")
                self._session_backends[session_id] = backend_choice

            return backend_choice

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as data_file:
        data_file.write(
            '{"command":"dispatcher-route","path":"/","response":"App_A"}\n'
        )
        data_file.flush()
        data_file_path = data_file.name
        print(f"Created data file at {data_file_path}")

    try:
        handler = TestDataHandler(
            data_file=data_file_path,
            system_prompt="Test prompt",
            model_id="test-model",
            structure={"command": "TEXT", "path": "TEXT"},
            routes=None,
        )

        honeypot = HTTPHoneypot(
            action=handler,
            config={
                "name": "TestHTTPDispatcher",
                "is_dispatcher": True,
            },
        )

        honeypot.session = HoneypotSession({"session_id": "test-session-id"})
        add_session_logging(honeypot)

        try:
            honeypot.start()

            time.sleep(1)

            client = requests.Session()
            url = f"http://127.0.0.1:{honeypot.port}/"

            print("\n=== First Request ===")
            response1 = debug_session(client, url)
            backend1 = response1.text

            time.sleep(0.5)

            print("\n=== Second Request ===")
            response2 = debug_session(client, url)
            backend2 = response2.text

            print(f"\n=== Test Results ===")
            print(f"First backend response: {backend1[:50]}...")
            print(f"Second backend response: {backend2[:50]}...")
            print(f"LLM calls made: {len(llm_calls)}")
            print(f"Session ID in cookies: {client.cookies.get('hp_session')}")
            print(f"Session map in honeypot: {getattr(honeypot, '_session_map', {})}")
            print(
                f"Session backends in handler: {getattr(handler, '_session_backends', {})}"
            )

            assert (
                backend1 == backend2
            ), f"ERROR: Backend responses don't match!\nFirst: {backend1}\nSecond: {backend2}"

            assert len(llm_calls) <= 1, f"ERROR: Too many LLM calls: {len(llm_calls)}"

            out, _ = capsys.readouterr()
            assert '"dd-honeypot": true' in out, "Missing dd-honeypot flag in logs"
            assert (
                '"name": "TestHTTPDispatcher"' in out
            ), "Missing dispatcher name in logs"

        finally:
            honeypot.stop()
            time.sleep(1)

    finally:
        try:
            os.unlink(data_file_path)
            print(f"Deleted data file {data_file_path}")
        except Exception as e:
            print(f"Error deleting data file: {e}")
