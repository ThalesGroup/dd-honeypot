from typing import Generator

import pytest

from http_honeypot import HTTPHoneypot
from honeypot_utils import allocate_port, init_env_from_file
from playwright.sync_api import sync_playwright

from honeypots.php_my_admin.php_my_admin import PhpMyAdminHoneypot
import time
import requests


@pytest.fixture
def http_honeypot() -> Generator[HTTPHoneypot, None, None]:
    honeypot = HTTPHoneypot(allocate_port())
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


def wait_for_http_service(port, path="/", timeout=5):
    url = f"http://127.0.0.1:{port}{path}"
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url)
            return r
        except requests.ConnectionError:
            time.sleep(0.2)
    raise RuntimeError(f"Server at {url} did not respond within {timeout} seconds")


@pytest.fixture
def php_my_admin() -> Generator[HTTPHoneypot, None, None]:
    honeypot = PhpMyAdminHoneypot(allocate_port())
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


@pytest.fixture(autouse=True, scope="module")
def set_evn():
    init_env_from_file()
    yield


def test_basic_http_request(http_honeypot):
    http_honeypot.connect({})
    wait_for_http_service(http_honeypot.port, "/path")
    requests.get(f"http://127.0.0.1:{http_honeypot.port}/path")
    response = requests.get(f"http://127.0.0.1:{http_honeypot.port}/path")
    assert response.status_code == 200
    assert "Request logged" in response.text


def test_php_my_admin(php_my_admin):
    php_my_admin.connect({})
    wait_for_http_service(php_my_admin.port, "/path")
    requests.get(f"http://127.0.0.1:{php_my_admin.port}/path")
    response = requests.get(f"http://127.0.0.1:{php_my_admin.port}/path")
    assert response.status_code == 404
    assert "Not Found" in response.text


@pytest.mark.skip(reason="Playwright is not installed in the CI environment")
def test_webdriver_http_request(php_my_admin):
    def log_request(request):
        # Filter for types that are usually triggered directly
        if request.resource_type in ["document", "xhr", "fetch"]:
            print(f">> {request.method} {request.url} ({request.resource_type})")
            if request.post_data:
                print(f"POST data: {request.post_data}")

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