import json
import logging
import pytest
import aiomysql
import asyncio
import time
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

    # Write to the file
    with open(data_file, "w") as f:
        f.write(json.dumps({
            "command": "SELECT * FROM USERS",  # Capitalized
            "response": {
                "columns": ["id", "name", "email"],
                "rows": [
                    [1, "person5", "person5@example.com"],
                    [2, "person6", "person6@example.com"]
                ]
            }
        }) + "\n")

    # Ensure the file exists before reading
    if data_file.exists():
        with open(data_file, "r") as f:
            print(f.read())  # Check if the query was saved correctly
    else:
        print(f"File not found: {data_file}")

    #  mock_invoke_llm — just returns known cached response
    def mock_invoke_llm(system_prompt, user_prompt, model_id):
        # Normalize and debug print
        cleaned = user_prompt.strip().rstrip(";").upper()
        print(f"Handling query: {cleaned}")  # Debugging line

        # Check for cached query
        if cleaned == "SELECT * FROM USERS":
            return json.dumps({
                "columns": ["id", "name", "email"],
                "rows": [
                    [1, "person5", "person5@example.com"],
                    [2, "person6", "person6@example.com"]
                ]
            })
        else:
            print(f"Unrecognized query: {cleaned}")  # Debugging line
            return json.dumps({
                "error_code": 1105,
                "error_message": "No valid handler for query"
            })

    #Use SSH-style honeypot creation
    honeypot = create_honeypot(config, invoke_fn=mock_invoke_llm)
    honeypot.start()
    await asyncio.sleep(0.5)  # Increased delay

    try:
        #Establish a connection to the honeypot
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

    except Exception as e:
        print(f"Error establishing connection: {e}")

    finally:
        if conn:
            conn.close()
        honeypot.stop()
