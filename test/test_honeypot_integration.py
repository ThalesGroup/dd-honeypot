import json
import pytest
from unittest.mock import patch, AsyncMock
import logging

from src.infra.data_handler import DataHandler
from src.mysql_honeypot import MySqlMimicHoneypot
import aiomysql
import asyncio
import contextlib

logging.getLogger("mysql_mimic").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.ERROR)


# Fixed port for honeypot
HONEYPOT_PORT = 13306



@contextlib.contextmanager
def suppress_asyncio_exceptions():
    loop = asyncio.get_event_loop()

    def ignore_exception_handler(loop, context):
        if 'exception' in context:
            return  # ignore
        loop.default_exception_handler(context)

    original_handler = loop.get_exception_handler()
    loop.set_exception_handler(ignore_exception_handler)
    try:
        yield
    finally:
        loop.set_exception_handler(original_handler)

@pytest.fixture
def temp_config(tmp_path):
    config = {
        "model_id": "mock-model",
        "system_prompt": "You are a MySQL server emulator.",
        "data_file": str(tmp_path / "mysql.jsonl")
    }

    test_data = {
        "SELECT * FROM users": {
            "columns": ["id", "name", "email"],
            "rows": [
                [1, "Alice", "alice@example.com"],
                [2, "Bob", "bob@example.com"]
            ]
        },
        "SHOW DATABASES": {
            "columns": ["Database"],
            "rows": [["testdb"], ["information_schema"]]
        }
    }

    with open(config["data_file"], "w") as f:
        for query, response in test_data.items():
            f.write(json.dumps({
                "command": query,
                "response": response
            }) + "\n")

    return config

@pytest.fixture
async def mysql_honeypot(temp_config):
    honeypot = MySqlMimicHoneypot(port=HONEYPOT_PORT, config=temp_config)
    honeypot.start()
    yield honeypot
    honeypot.stop()

@pytest.fixture
async def mysql_connection(mysql_honeypot):
    conn = await aiomysql.connect(
        host="127.0.0.1",
        port=HONEYPOT_PORT,
        user="test",
        password="123",
        db="testdb",
        connect_timeout=5
    )
    yield conn
    conn.close()

@pytest.mark.asyncio
async def test_mysql_honeypot_with_data_handler(temp_config):
    async def mock_get_data(query=None, **kwargs):
        print(f"mock_get_data called with: {query}")
        normalized = query.strip().rstrip(";").upper() if query else ""
        if normalized == "SELECT * FROM USERS":
            return {
                "columns": ["id", "name", "email"],
                "rows": [
                    (1, "Alice", "alice@example.com"),
                    (2, "Bob", "bob@example.com")
                ]
            }
        return {
            "columns": ["Database"],
            "rows": [("testdb",), ("information_schema",)]
        }

    with suppress_asyncio_exceptions():
        with patch.object(DataHandler, "get_data", new=AsyncMock(side_effect=mock_get_data)):
            honeypot = MySqlMimicHoneypot(port=HONEYPOT_PORT, config=temp_config)
            honeypot.start()

            try:
                conn = await aiomysql.connect(
                    host="127.0.0.1",
                    port=HONEYPOT_PORT,
                    user="test",
                    password="123",
                    db="testdb",
                    connect_timeout=5,
                )

                async with conn.cursor() as cursor:
                    await cursor.execute("SELECT * FROM users")
                    rows = await cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description]

                    assert columns == ["id", "name", "email"]
                    assert list(rows) == [
                        (1, "Alice", "alice@example.com"),
                        (2, "Bob", "bob@example.com"),
                    ]
            finally:
                honeypot.stop()