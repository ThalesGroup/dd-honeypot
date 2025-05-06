import json
import pytest
from unittest.mock import patch
from src.mysql_honeypot import MySqlMimicHoneypot
import aiomysql

@pytest.fixture
def temp_config(tmp_path):
    """Create temporary configuration and test data"""
    config = {
        "model_id": "mock-model",
        "system_prompt": "You are a MySQL server emulator.",
        "data_file_path": str(tmp_path / "mysql_data.jsonl")
    }

    # Create test data
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

    with open(config["data_file_path"], "w") as f:
        for query, response in test_data.items():
            f.write(json.dumps({
                "command": query,
                "response": response
            }) + "\n")

    return config

@pytest.fixture
async def mysql_honeypot(unused_tcp_port, temp_config):
    honeypot = MySqlMimicHoneypot(port=unused_tcp_port, config=temp_config)
    honeypot.start()
    yield honeypot
    honeypot.stop()

@pytest.fixture
async def mysql_connection(mysql_honeypot, unused_tcp_port):
    conn = await aiomysql.connect(
        host='127.0.0.1',
        port=unused_tcp_port,
        user='test',
        password='123',
        db='testdb',
        connect_timeout=5
    )
    yield conn
    conn.close()

@pytest.mark.asyncio
async def test_mysql_honeypot_with_data_handler(temp_config, unused_tcp_port):
    """Integration test verifying MySQL honeypot returns responses from data handler"""

    # Patch the correct path to DataHandler
    with patch("src.infra.data_handler.DataHandler.get_data") as mock_get_data:
        mock_get_data.side_effect = lambda sql, user_prompt=None: {
            "columns": ["id", "name", "email"],
            "rows": [
                [1, "Alice", "alice@example.com"],
                [2, "Bob", "bob@example.com"]
            ]
        } if sql.strip() == "SELECT * FROM users" else {
            "columns": ["Database"],
            "rows": [["testdb"], ["information_schema"]]
        }

        # Start honeypot
        honeypot = MySqlMimicHoneypot(port=unused_tcp_port, config=temp_config)
        honeypot.start()

        try:
            conn = await aiomysql.connect(
                host="127.0.0.1",
                port=unused_tcp_port,
                user="test",
                password="123",
                db="testdb",
                connect_timeout=5
            )

            async with conn.cursor() as cursor:
                await cursor.execute("SELECT * FROM users")
                result = await cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]

                assert columns == ["id", "name", "email"]
                assert result == [
                    (1, "Alice", "alice@example.com"),
                    (2, "Bob", "bob@example.com")
                ]

                await cursor.execute("SHOW DATABASES")
                result = await cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]

                assert columns == ["Database"]
                assert ("testdb",) in result
                assert ("information_schema",) in result

        finally:
            honeypot.stop()
