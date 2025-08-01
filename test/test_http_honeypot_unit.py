import json
import os.path
import tempfile
import threading
import time
from typing import Generator

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

    honeypot = HTTPHoneypot(
        action=TestHTTPDataHandler(), config={"name": "TestHTTPHoneypot"}
    )
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
    honeypot = create_honeypot(config)
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
