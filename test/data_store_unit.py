import json
from tempfile import NamedTemporaryFile

import pytest

from infra.data_store import SearchMethod
from src.infra.data_store import SqliteDataStore


@pytest.fixture
def cmd_ds():
    with NamedTemporaryFile() as temp_file:
        yield SqliteDataStore(
            db_name=temp_file.name,
            structure={"command": "TEXT"},
            search_method={"command": SearchMethod.EXACT},
        )


def test_store_and_search(cmd_ds):
    command = "ls -la"
    cmd_ds.store({"command": command}, "Mocked response")
    result = cmd_ds.search({"command": command})
    assert "Mocked response" in result
    assert cmd_ds.delete({"command": command})

    assert cmd_ds.search({"command": command}) is None
    result = cmd_ds.search({"command": "pwd"})
    assert not result


def test_clear(cmd_ds):
    assert cmd_ds.clear() == 0
    command = "ls -la"
    cmd_ds.store({"command": command}, "Mocked response")
    result = cmd_ds.search({"command": command})
    assert "Mocked response" in result
    assert cmd_ds.clear() == 1
    assert cmd_ds.clear() == 0


def test_static_content_loading(cmd_ds):
    with NamedTemporaryFile() as temp_file:
        temp_file.write(b'{"command": "ls -la", "response": "Mocked response"}')
        temp_file.flush()
        cmd_ds.load_static_content(temp_file.name)
    result = cmd_ds.search({"command": "ls -la"})
    assert "Mocked response" in result


def test_dump(cmd_ds):
    with NamedTemporaryFile() as temp_file:
        cmd_ds.store({"command": "ls -la"}, "Mocked response")
        dumped_count = cmd_ds.dump(temp_file.name)
        assert dumped_count == 1

        with open(temp_file.name, "r") as f:
            content = f.read()
    json_content = json.loads(content)
    assert json_content["command"] == "ls -la"
    assert json_content["response"] == "Mocked response"


@pytest.fixture
def http_ds():
    with NamedTemporaryFile() as temp_file:
        yield SqliteDataStore(
            db_name=temp_file.name,
            structure={"path": "TEXT", "args": "TEXT", "body": "TEXT"},
            search_method={},
        )


def test_http_store_and_search(http_ds):
    http_ds.store({"path": "/"}, "<html>Mocked response</html>")
    assert http_ds.search({"path": "/"}) == "<html>Mocked response</html>"
    http_ds.store({"path": "/", "args": "a=1&b=2"}, "<html>Mocked response ab</html>")
    assert (
        http_ds.search({"path": "/", "args": "a=1&b=2"})
        == "<html>Mocked response ab</html>"
    )
    assert http_ds.search({"path": "/", "args": "a=1"}) is None
