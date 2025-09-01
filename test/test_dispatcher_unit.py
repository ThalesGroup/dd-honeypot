import hashlib
from unittest.mock import patch

import pytest

# from dispatcher import ProtocolDispatcher
import os

from http_data_handlers import HTTPDataHandler
from infra.data_handler import DataHandler
from ssh_honeypot import SSHHoneypot


@pytest.fixture
def dispatcher():
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    backend_map = {
        "php_my_admin": HTTPDataHandler,
        "boa_server_http": HTTPDataHandler,
        "mysql_ssh": SSHHoneypot,
        "default": DataHandler,
    }
    return ProtocolDispatcher(
        "honeypots/protocol_dispatcher/dispatcher_config.json", backend_map
    )


@pytest.mark.skip("Enable after implementation")
def test_load_config(dispatcher):
    assert "php_my_admin" in dispatcher.config["handlers"]
    assert dispatcher.config["llm"]["system_prompt"]


@pytest.mark.skip("Enable after implementation")
def test_route_with_llm(dispatcher):
    with patch("infra.data_handler.invoke_llm", return_value="php_my_admin"):
        assert dispatcher.route("/phpmyadmin/login") == "php_my_admin"


@pytest.mark.skip("Enable after implementation")
def test_route_with_cache(dispatcher):
    cache_key = {"command": f"route:{hashlib.md5('/login.htm'.encode()).hexdigest()}"}
    dispatcher.data_handler._data_store.store(cache_key, "boa_server_http")

    assert dispatcher.route("/login.htm") == "boa_server_http"


@pytest.mark.skip("Enable after implementation")
def test_fallback_to_default(dispatcher):
    if hasattr(dispatcher.data_handler._data_store, "clear"):
        dispatcher.data_handler._data_store.clear()
    with patch("infra.data_handler.invoke_llm", return_value="invalid"):
        assert dispatcher.route("/unknown") == "default"
