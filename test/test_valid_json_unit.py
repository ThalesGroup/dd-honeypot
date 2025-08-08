import logging
import sqlite3

from infra.data_store import SqliteDataStore


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
