import hashlib
import json
import os
from unittest.mock import patch

import pytest

from http_data_handlers import HTTPDataHandler
from infra.bootstrap import ssh_hp
from infra.data_handler import DataHandler
from infra.protocol_dispatcher import ProtocolDispatcher


class DummyDataStore:
    def __init__(self):
        self._cache = {}

    def store(self, key, value):
        # Store with the command as key for caching
        if isinstance(key, dict) and "command" in key:
            self._cache[key["command"]] = value
        else:
            self._cache[str(key)] = value

    def clear(self):
        self._cache.clear()

    def get(self, key):
        if isinstance(key, dict) and "command" in key:
            return self._cache.get(key["command"])
        return self._cache.get(str(key))


class DummyDataHandler:
    def __init__(self):
        self._data_store = DummyDataStore()


@pytest.fixture
def dispatcher():
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    backend_map = {
        "php_my_admin": HTTPDataHandler("dummy.json", "some_prompt", "model_id"),
        "boa_server_http": HTTPDataHandler("dummy.json", "some_prompt", "model_id"),
        "mysql_ssh": ssh_hp,
        "default": DataHandler("dummy.json", "some_prompt", "model_id"),
    }

    base_dir = os.path.dirname(__file__)  # tests directory
    config_path = os.path.join(base_dir, "honeypots", "http_dispatcher", "config.json")
    with open(config_path, "r") as f:
        config = json.load(f)
    disp = ProtocolDispatcher(config, backend_map)

    disp.data_handler = DummyDataHandler()

    return disp


def test_load_config(dispatcher):
    assert "honeypots" in dispatcher.config
    assert dispatcher.config["system_prompt"]

    handler_instance = dispatcher.route(session_id="sess1", first_req="/phpmyadmin")
    handler_name = getattr(handler_instance, "name", None)
    if handler_name is None:
        reverse_map = {v: k for k, v in dispatcher.backends.items()}
        handler_name = reverse_map.get(handler_instance)
    assert handler_name in dispatcher.config["honeypots"]


def test_route_with_llm(dispatcher):
    with patch("infra.data_handler.invoke_llm", return_value="php_my_admin"):
        session_id = "session_1"
        first_req = "/phpmyadmin/login"
        result = dispatcher.route(session_id, first_req)
        assert result == dispatcher.backends["php_my_admin"]


def test_route_with_cache(dispatcher):
    cache_key = {"command": f"route:{hashlib.md5('/login.htm'.encode()).hexdigest()}"}
    dispatcher.data_handler._data_store.store(cache_key, "boa_server_http")

    session_id = "session_2"
    first_req = "/login.htm"
    result = dispatcher.route(session_id, first_req)
    assert result == dispatcher.backends["boa_server_http"]


def test_fallback_to_default(dispatcher):
    if hasattr(dispatcher.data_handler._data_store, "clear"):
        dispatcher.data_handler._data_store.clear()

    with patch("infra.data_handler.invoke_llm", return_value="invalid"):
        session_id = "session_3"
        first_req = "/unknown"
        result = dispatcher.route(session_id, first_req)
        assert result == dispatcher.backends["default"]
