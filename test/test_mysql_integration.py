import json
import pytest
from unittest.mock import patch, AsyncMock
import logging

from src.infra.data_handler import DataHandler
from src.mysql_honeypot import MySqlMimicHoneypot
import aiomysql
import asyncio
import contextlib

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

# Main test using the honeypot + mocking DataHandler.get_data
@pytest.mark.asyncio
async def test_mysql_honeypot_with_data_handler(temp_config):
    # Mock function to simulate DataHandler.get_data
    async def mock_get_data(query=None, **kwargs):
        print(f"mock_get_data called with: {query}")
        normalized = query.strip().rstrip(";").upper() if query else ""
        if normalized == "SELECT * FROM USERS":
            return {
                "columns": ["id", "name", "email"],
                "rows": [
                    (1, "person5", "person5@example.com"),
                    (2, "person6", "person6@example.com")
                ]
            }
        return {
            "columns": ["Database"],
            "rows": [("testdb",), ("information_schema",)]
        }

    # Patch DataHandler.get_data with our mock during the test
    with suppress_asyncio_exceptions():
        with patch.object(DataHandler, "get_data", new=AsyncMock(side_effect=mock_get_data)):
            honeypot = MySqlMimicHoneypot(port=HONEYPOT_PORT, config=temp_config)
            honeypot.start()

            try:
                # Connect to the honeypot via aiomysql
                conn = await aiomysql.connect(
                    host="127.0.0.1",
                    port=HONEYPOT_PORT,
                    user="test",
                    password="123",
                    db="testdb",
                    connect_timeout=5,
                )

                # Execute a SQL query and check that the mock response is returned
                async with conn.cursor() as cursor:
                    await cursor.execute("SELECT * FROM users")
                    rows = await cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description]

                    # Validate the returned column names and row data
                    assert columns == ["id", "name", "email"]
                    assert list(rows) == [
                        (1, "person5", "person5@example.com"),
                        (2, "person6", "person6@example.com"),
                    ]
            finally:
                honeypot.stop()
