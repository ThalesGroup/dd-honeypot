from typing import Generator

import pytest
import requests

import socket
import time

from HttpHoneypot import HTTPHoneypot
from honeypot_utils import allocate_port
from playwright.sync_api import sync_playwright

from honeypots.php_my_admin.php_my_admin import PhpMyAdminHoneypot

def wait_for_http_ready(port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except (ConnectionRefusedError, socket.timeout):
            time.sleep(0.5)
    raise RuntimeError(f"HTTP honeypot on port {port} failed to start within timeout")

@pytest.fixture
def http_honeypot() -> Generator[HTTPHoneypot, None, None]:
    honeypot = HTTPHoneypot(allocate_port())
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


@pytest.fixture
def php_my_admin() -> Generator[HTTPHoneypot, None, None]:
    honeypot = PhpMyAdminHoneypot(allocate_port())
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()

def test_basic_http_request(http_honeypot):
    http_honeypot.connect({})
    wait_for_http_ready(http_honeypot.port)

    response = requests.get(f"http://localhost:{http_honeypot.port}/path")
    assert response.status_code == 200
    assert "Request logged" in response.text


def test_php_my_admin(php_my_admin):
    php_my_admin.connect({})
    wait_for_http_ready(php_my_admin.port)

    response = requests.get(f"http://localhost:{php_my_admin.port}/path")
    assert response.status_code == 404
    assert "Not Found" in response.text


@pytest.mark.skip(reason="Requires Playwright to be installed and configured")
def test_webdriver_http_request(php_my_admin):
    with sync_playwright() as p, p.chromium.launch(
        headless=False
    ) as browser, browser.new_page() as page:
        page.goto(f"http://localhost:{php_my_admin.port}")
        page.fill('input[name="pma_username"]', "root")
        page.fill('input[name="pma_password"]', "rootpassword")
        page.click("input#input_go")
        page.wait_for_load_state("networkidle")
        try:
            page.wait_for_selector('a:has-text("SQL")', timeout=5000)
            print("✅ Login successful — SQL tab found!")
        except TimeoutError:
            error = page.query_selector(".error")
            if error:
                print("❌ Login failed:", error.inner_text())
            else:
                print("❌ Login failed or SQL tab not found.")
