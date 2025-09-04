import os
import json
import pytest

from infra.dispatcher_utils import DispatcherUtils
from http_data_handlers import HTTPDataHandler


@pytest.fixture
def config():
    path = os.path.join(
        os.path.dirname(__file__), "honeypots", "http_dispatcher", "config.json"
    )
    with open(path, "r") as f:
        return json.load(f)


@pytest.fixture
def data():
    path = os.path.join(
        os.path.dirname(__file__), "honeypots", "http_dispatcher", "data.jsonl"
    )
    with open(path, "r") as f:
        return [json.loads(line) for line in f]


@pytest.fixture
def handler():
    return HTTPDataHandler


@pytest.fixture
def dispatcher():
    from infra.bootstrap import http_dispatcher

    return http_dispatcher


def test_config_load(dispatcher):
    assert dispatcher.config["type"] == "http"
    assert "honeypots" in dispatcher.config
    assert isinstance(dispatcher.config["system_prompt"], list)
    assert dispatcher.config["port"] == 80


def test_subhandler_descriptions(dispatcher):
    for name in dispatcher.config["honeypots"]:
        descriptions = DispatcherUtils(dispatcher.backends).get_handler_descriptions()
        desc = descriptions[name]
        assert desc and isinstance(desc, str)


def test_routing(dispatcher):
    handler_instance = dispatcher.route(session_id="sess1", first_req="/phpmyadmin")
    handler_name = getattr(handler_instance, "name", None)
    if handler_name is None:
        reverse_map = {v: k for k, v in dispatcher.backends.items()}
        handler_name = reverse_map.get(handler_instance)
    assert handler_name in dispatcher.config["honeypots"]


def test_routing_unknown(dispatcher):
    handler_instance = dispatcher.route(session_id="sess1", first_req="/unknown_path")
    handler_name = getattr(handler_instance, "name", None)
    if handler_name is None:
        reverse_map = {v: k for k, v in dispatcher.backends.items()}
        handler_name = reverse_map.get(handler_instance)
    assert handler_name in dispatcher.config["honeypots"]


def test_session_persistence(dispatcher):
    session = "sess_id"
    first = dispatcher.route(session, "/unknown")
    second = dispatcher.route(session, "/another")
    assert first == second
