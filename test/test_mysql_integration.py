import json
import logging
import pytest
import aiomysql
import asyncio
import contextlib
from pathlib import Path
from src.infra.honeypot_wrapper import create_honeypot

logging.getLogger("mysql_mimic").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.ERROR)

HONEYPOT_PORT = 13306

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

    # Pre-fill mock cache
    cached = {
        "SELECT * FROM users": {
            "columns": ["id", "name", "email"],
            "rows": [
                [1, "person5", "person5@example.com"],
                [2, "person6", "person6@example.com"]
            ]
        }
    }

    with open(data_file, "w") as f:
        for cmd, resp in cached.items():
            f.write(json.dumps({"command": cmd, "response": resp}) + "\n")

    # MockDataHandler compatible with HoneypotAction
    class MockDataHandler:
        def connect(self, auth_info: dict):
            return type("Session", (), {"session_id": "mock", "info": {}})()

        def query(self, query: str, session, **kwargs):
            cleaned = query.strip().rstrip(";").upper()
            if cleaned == "SELECT * FROM USERS":
                return {
                    "columns": ["id", "name", "email"],
                    "rows": [
                        (1, "person5", "person5@example.com"),
                        (2, "person6", "person6@example.com")
                    ]
                }
            return None

    honeypot = create_honeypot(config, command_handler=MockDataHandler())
    honeypot.start()
    await asyncio.sleep(0.2)

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

            assert result == [
                (1, "person5", "person5@example.com"),
                (2, "person6", "person6@example.com")
            ]

    finally:
        conn.close()
        honeypot.stop()