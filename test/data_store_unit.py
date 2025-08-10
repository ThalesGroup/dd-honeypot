import json
import logging
import os
import sqlite3
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


def test_missing_db_file_recovers_gracefully():
    """Test that SqliteDataStore works even if the DB file is deleted after creation."""
    with NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name

    # Create initial store and add an entry
    store = SqliteDataStore(
        db_name=temp_path,
        structure={"command": "TEXT"},
        search_method={"command": SearchMethod.EXACT},
    )
    store.store({"command": "whoami"}, "user=root")

    # Delete the underlying DB file
    os.remove(temp_path)
    assert not os.path.exists(temp_path)

    # Re-initialize store - this should recreate the DB and NOT crash
    store = SqliteDataStore(
        db_name=temp_path,
        structure={"command": "TEXT"},
        search_method={"command": SearchMethod.EXACT},
    )
    # It should be empty now, but not crash
    result = store.search({"command": "whoami"})
    assert result is None


def test_loader_skips_invalid_lines_and_loads_valid(tmp_path, caplog):
    # Data: 2 valid, 1 missing required key, 1 invalid JSON line
    data = (
        '{"path": "/good", "response": "<html>ok</html>"}\n'
        '{"path": "/bad"}\n'  # missing "response"
        "notjson\n"  # invalid JSON
        '{"path": "/good2", "response": "<html>ok2</html>"}\n'
    )

    db_file = tmp_path / "test.db"
    db_name = str(db_file)
    structure = {"path": "TEXT"}

    ds = SqliteDataStore(db_name=db_name, structure=structure)

    data_path = tmp_path / "test_data.txt"
    data_path.write_text(data)

    with caplog.at_level(logging.ERROR):
        ds.load_static_content(str(data_path))

    with sqlite3.connect(db_name) as conn:
        cursor = conn.execute(
            f"SELECT path, data FROM {ds._TABLE_NAME} WHERE is_static = 1"
        )
        rows = list(cursor)

    assert len(rows) == 2
    loaded_paths = [row[0] for row in rows]
    assert "/good" in loaded_paths
    assert "/good2" in loaded_paths

    assert "Missing required key" in caplog.text
    assert "Invalid JSON" in caplog.text
