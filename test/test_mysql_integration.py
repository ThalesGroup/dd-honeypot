import json
import logging
import pytest
import aiomysql
import asyncio
import contextlib
from pathlib import Path
from unittest.mock import MagicMock
from src.infra.honeypot_wrapper import create_honeypot
from src.mysql_honeypot import MySqlMimicHoneypot

# Reduce noise in test output from internal logs
logging.getLogger("mysql_mimic").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.ERROR)

# Fixed port for running the honeypot
HONEYPOT_PORT = 13306

# Suppresses unwanted asyncio exception logs during tests
@contextlib.contextmanager
def suppress_asyncio_exceptions():
    loop = asyncio.get_event_loop()

    def ignore_exception_handler(loop, context):
        exception = context.get("exception")
        if isinstance(exception, ConnectionResetError):
            return  # Suppress known MySQL handshake issue
        if exception and "Connection lost" in str(exception):
            return  # Fallback: suppress based on message
        loop.default_exception_handler(context)  # Pass others to default

    original_handler = loop.get_exception_handler()
    loop.set_exception_handler(ignore_exception_handler)
    try:
        yield
    finally:
        loop.set_exception_handler(original_handler)

# Temporary test config fixture for the MySQL honeypot
@pytest.fixture
def temp_config(tmp_path):
    config = {
        "model_id": "mock-model",
        "system_prompt": "You are a MySQL server emulator.",
        "data_file": str(tmp_path / "mysql.jsonl")  # Temp file for query/response cache
    }

    # Sample queries and expected responses written to data_file
    test_data = {
        "SELECT * FROM users": {
            "columns": ["id", "name", "email"],
            "rows": [
                [1, "person5", "person5@example.com"],
                [2, "person6", "person6@example.com"]
            ]
        },
        "SHOW DATABASES": {
            "columns": ["Database"],
            "rows": [["testdb"], ["information_schema"]]
        }
    }

    # Write test data to the JSONL cache file
    with open(config["data_file"], "w") as f:
        for query, response in test_data.items():
            f.write(json.dumps({
                "command": query,
                "response": response
            }) + "\n")

    return config

# Fixture to start/stop the honeypot around each test
@pytest.fixture
async def mysql_honeypot(temp_config):
    honeypot = MySqlMimicHoneypot(port=HONEYPOT_PORT, config=temp_config)
    honeypot.start()
    yield honeypot
    honeypot.stop()

# Fixture to connect to the honeypot using aiomysql
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

# Main test using the honeypot (no DataHandler)
@pytest.mark.asyncio
async def test_mysql_honeypot_integration(tmp_path: Path):
    data_file = tmp_path / "mysql.jsonl"
    config = {
        "type": "mysql",
        "port": HONEYPOT_PORT,
        "data_file": str(data_file),
        "system_prompt": "You are a MySQL server emulator.",
        "model_id": "mock-model"
    }

    class MockDataHandler:
        def sync_get(self, query):
            query = query.strip().rstrip(";").upper()
            if query == "SELECT * FROM USERS":
                return {
                    "columns": ["id", "name", "email"],
                    "rows": [
                        [1, "person5", "person5@example.com"],
                        [2, "person6", "person6@example.com"]
                    ]
                }
            return None  # Ensure we return None if no match

        async def get_data(self, query):
            # Async interface expected by the honeypot
            response = self.sync_get(query)
            if not response:
                return None

            columns = response.get("columns", [])
            rows = [tuple(r) for r in response.get("rows", [])]  # normalize

            return {"columns": columns, "rows": rows}

        def handle_query(self, query):
            response = self.sync_get(query)
            columns = response.get("columns", [])
            rows = response.get("rows", [])
            rows = [tuple(r) for r in rows]  # normalize to tuple format
            return {"columns": columns, "rows": rows}

    honeypot = create_honeypot(config, command_handler=MockDataHandler())

    honeypot.start()
    await asyncio.sleep(0.1)  # Let it initialize

    try:
        conn = await aiomysql.connect(
            host="127.0.0.1",
            port=HONEYPOT_PORT,
            user="test",
            password="123",
            db="testdb",
            connect_timeout=5
        )

        async with conn.cursor() as cursor:
            await cursor.execute("SELECT * FROM users")
            result = await cursor.fetchall()
            assert list(result) == [
                (1, "person5", "person5@example.com"),
                (2, "person6", "person6@example.com")
            ]
    finally:
        conn.close()
        honeypot.stop()
