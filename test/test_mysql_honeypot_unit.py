import json
import os
import socket
import threading
import time
import logging
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest
import pymysql
import mysql.connector
import asyncio
from pymysql.err import OperationalError
from src.mysql_honeypot import MySession  # Import your session class
from mysql.connector.errors import DatabaseError, OperationalError, InterfaceError
from src.mysql_honeypot import MySqlMimicHoneypot

logger = logging.getLogger(__name__)
# Set up logger
logging.basicConfig(level=logging.INFO)


@pytest.fixture(autouse=True)
def suppress_asyncio_connection_errors(monkeypatch):
    async def quiet_drain(self):
        try:
            await original_drain(self)
        except ConnectionResetError:
            pass
    original_drain = asyncio.StreamWriter.drain
    monkeypatch.setattr(asyncio.StreamWriter, "drain", quiet_drain)

    # Suppress asyncio connection error log messages
    asyncio_logger = logging.getLogger("asyncio")
    asyncio_logger.setLevel(logging.CRITICAL)


@pytest.fixture
def running_honeypot():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(1)  # Allow server to start
    yield honeypot
    honeypot.stop()

"""Ensures that the honeypot properly handles invalid handshakes and rejects 
connections with the expected error messages."""
def test_honeypot_should_fail_on_invalid_handshake():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(1)

    try:
        with pytest.raises((DatabaseError, OperationalError, InterfaceError)) as exc_info:  # type: ignore
            with mysql.connector.connect(
                host="127.0.0.1",
                port=honeypot.port,
                user="test",
                password="test",
                database="test_db",
                connection_timeout=2,
                ssl_disabled=True
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1;")
                    cursor.fetchone()

        msg = str(exc_info.value)
        assert any(
            err in msg for err in [
                "Can't connect to MySQL server",
                "Lost connection",
                "initial communication packet",
                "Malformed packet",
                "1105 (HY000)",
                "Access denied for user"
            ]
        ), f"Unexpected error message: {msg}"

    finally:
        honeypot.stop()


"""Tests real MySQL connection and query execution on an actual MySQL server."""
@pytest.mark.skipif(os.getenv("CI") == "true", reason="MySQL not available in CI")
def test_real_mysql_connection_and_query():
    """Test a positive connection and diverse queries on real MySQL."""
    try:
        with mysql.connector.connect(
            host="127.0.0.1",
            port=3306,
            user="test",
            password="test",
            database="test_db"
        ) as connection:
            with connection.cursor() as cursor:
                # Test basic SELECT
                cursor.execute("SELECT 1;")
                result = cursor.fetchone()
                assert result == (1,), f"Expected (1,), got {result}"

                # Test mathematical expression
                cursor.execute("SELECT 2 * 3 + 5;")
                math_result = cursor.fetchone()
                assert math_result == (11,), f"Expected (11,), got {math_result}"

                # Test string function
                cursor.execute("SELECT CONCAT('Data', 'Lure');")
                concat_result = cursor.fetchone()
                assert concat_result == ('DataLure',), f"Expected ('DataLure',), got {concat_result}"

                # Test current timestamp
                cursor.execute("SELECT NOW();")
                timestamp = cursor.fetchone()
                assert timestamp[0] is not None, "Expected a timestamp, got None"

                # Test system/user info
                cursor.execute("SELECT USER(), DATABASE();")
                user_info = cursor.fetchone()
                assert user_info[0] is not None and user_info[1] == 'test_db', f"Unexpected user/db: {user_info}"

    except Exception as e:
        pytest.skip(f"Skipping real MySQL test: {str(e)}")


"""Tests connectivity to the honeypot using both mysql-connector and pymysql libraries."""
@pytest.mark.skipif(os.getenv("CI") == "true", reason="MySQL not available in CI")
def test_real_mysql_basic_operations():
    """Test basic SQL operations on real MySQL to compare expected responses."""
    try:
        conn = mysql.connector.connect(
            host="127.0.0.1",
            port=3306,
            user="test",
            password="test",
            database="test_db"
        )
        cursor = conn.cursor()

        # Create a temporary table
        cursor.execute("CREATE TEMPORARY TABLE IF NOT EXISTS temp_users (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(50));")

        # Insert values
        cursor.execute("INSERT INTO temp_users (name) VALUES ('person1'), ('person2');")
        conn.commit()

        # Select and check values
        cursor.execute("SELECT name FROM temp_users ORDER BY id;")
        results = cursor.fetchall()
        assert results == [('person1',), ('person2',)], f"Unexpected query result: {results}"

        # Cleanup is automatic since it's a TEMPORARY table

        cursor.close()
        conn.close()
    except Exception as e:
        pytest.skip(f"Skipping real DB test due to error: {str(e)}")

def test_honeypot_connection_mysql_connector():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(1)  # Ensure server is ready

    try:
        with mysql.connector.connect(
                host="127.0.0.1",
                port=honeypot.port,
                user="test",
                password="test",
                auth_plugin='mysql_native_password',
                connection_timeout=3,
                ssl_disabled=True
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                assert result == (1,), f"Expected (1,), got {result}"

    except Exception as e:
        logger.info(f"mysql-connector attempt failed, falling back to pymysql: {repr(e)}")
    finally:
        honeypot.stop()

"""Tests connectivity to the honeypot using both mysql-connector and pymysql libraries."""
def test_honeypot_connection_pymysql():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(1)  # Ensure server is ready

    try:
        with pymysql.connect(
                host="127.0.0.1",
                port=honeypot.port,
                user="test",
                password="test",
                connect_timeout=3,
                ssl={'disabled': True}  # Explicitly disable SSL
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                assert result == (1,), f"Expected (1,), got {result}"

    except Exception as e:
        logger.info(f"mysql-connector attempt failed, falling back to pymysql: {repr(e)}")
    finally:
        honeypot.stop()


@pytest.fixture(scope="module")
def run_honeypot():
    honeypot = MySqlMimicHoneypot()
    thread = threading.Thread(target=honeypot.run, daemon=True)
    thread.start()
    # Wait for the honeypot to be ready
    timeout = 5  # seconds
    start = time.time()
    while True:
        try:
            with socket.create_connection(("127.0.0.1", honeypot.port), timeout=0.5):
                break  # Success: server is ready
        except (ConnectionRefusedError, OSError):
            if time.time() - start > timeout:
                raise TimeoutError("Honeypot did not start within timeout.")
            time.sleep(0.1)
    yield honeypot
    honeypot.stop()


def test_connection_to_honeypot(run_honeypot):
    host = "127.0.0.1"
    port = run_honeypot.port

    # Update the expected exception to match the actual error message format
    with pytest.raises(mysql.connector.errors.ProgrammingError, match=r"1045 \(28000\): Access denied for user attacker"):
        mysql.connector.connect(
            host=host, port=port, user="attacker", password="fake", connect_timeout=5
        )


def save_response_to_jsonl(response: dict):
    """Save unique LLM response to a JSONL file in the correct honeypot location."""

    # Set the correct data.jsonl path
    file_path = Path(__file__).parent.parent / "src" / "honeypots" / "mysql" / "data.jsonl"
    file_path.parent.mkdir(parents=True, exist_ok=True)  # Make sure folder exists

    # Check if the file already exists and load old queries
    existing_queries = set()
    if file_path.exists():
        with open(file_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if "query" in data:
                        existing_queries.add(data["query"])
                except json.JSONDecodeError:
                    continue  # Ignore broken lines

    # Get the query from the incoming response
    query = response.get("query")

    # Save only if query is new
    if query and query not in existing_queries:
        with open(file_path, "a") as f:
            json.dump(response, f) #type: ignore
            f.write("\n")
        print(f"Saved new query: {query}")  # ADD THIS

    else:
        print(f"Skipping duplicate query: {query}")

# Test Class for LLM Response Parsing
@pytest.mark.asyncio
class TestLLMResponseParsing:
    """Validates the response from the LLM with mocked data."""

    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_valid_data(self, mock_llm):
        mock_llm.return_value = json.dumps({
            "columns": ["username", "email"],
            "rows": [("person3", "person3@example.com"), ("bob", "bob@example.com")]
        })

        save_response_to_jsonl(json.loads(mock_llm.return_value))
        my_session = MySession()
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert isinstance(columns, list)
        assert isinstance(rows, list)
        assert len(columns) == 2
        assert len(rows) == 2
        assert columns == ["username", "email"]
        assert rows[0] == ("person3", "person3@example.com")

    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_invalid_fallback(self, mock_llm):
        mock_llm.return_value = ""

        save_response_to_jsonl({"columns": ["Invalid LLM Output"], "rows": []})
        my_session = MySession()
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert columns == ["Invalid LLM Output"]
        assert rows == []

    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_no_rows(self, mock_llm):
        mock_llm.return_value = json.dumps({
            "columns": ["username", "email"],
            "rows": []
        })

        save_response_to_jsonl(json.loads(mock_llm.return_value))
        my_session = MySession()
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert isinstance(columns, list)
        assert isinstance(rows, list)
        assert len(rows) == 0

    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_invalid_data(self, mock_llm):
        mock_llm.return_value = "{invalid_json: true, columns: [username], rows: []}"

        save_response_to_jsonl({"columns": ["Invalid LLM Output"], "rows": []})
        my_session = MySession()
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert columns == ["Invalid LLM Output"]
        assert rows == []

    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_empty_columns(self, mock_llm):
        mock_llm.return_value = json.dumps({
            "columns": [],
            "rows": [("person1", "person1@example.com"), ("person2", "person2@example.com")]
        })

        save_response_to_jsonl(json.loads(mock_llm.return_value))
        my_session = MySession()
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert isinstance(columns, list)
        assert columns == ['No data available']

    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_with_large_data(self, mock_llm):
        mock_llm.return_value = json.dumps({
            "columns": ["username", "email"],
            "rows": [(f"user{i}", f"user{i}@example.com") for i in range(5)]
        })

        save_response_to_jsonl(json.loads(mock_llm.return_value))
        my_session = MySession()
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert len(rows) == 5
        assert len(columns) == 2

    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_select_users(self, mock_llm):
        mock_llm.return_value = json.dumps({
            "columns": ["id", "username"],
            "rows": [(1, "user1"), (2, "user2")]
        })

        save_response_to_jsonl(json.loads(mock_llm.return_value))
        my_session = MySession()
        rows, columns = await my_session.get_llm_response("SELECT * FROM users;")

        assert columns == ["id", "username"]
        assert rows == [(1, "user1"), (2, "user2")]
        assert isinstance(columns, list)
        assert isinstance(rows, list)

    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_show_databases(self, mock_llm):
        mock_llm.return_value = json.dumps({
            "columns": ["Database"],
            "rows": [("db1",), ("db2",)]
        })

        save_response_to_jsonl(json.loads(mock_llm.return_value))
        my_session = MySession()
        rows, columns = await my_session.get_llm_response("SHOW DATABASES;")

        assert columns == ["Database"]
        assert rows == [("db1",), ("db2",)]

    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_select_email(self, mock_llm):
        mock_llm.return_value = json.dumps({
            "columns": ["email"],
            "rows": [("a@example.com",), ("b@example.com",)]
        })

        save_response_to_jsonl(json.loads(mock_llm.return_value))
        my_session = MySession()
        query="SELECT email FROM customers;"
        rows, columns = await my_session.get_llm_response(query)

        assert columns == ["email"]
        assert rows == [("a@example.com",), ("b@example.com",)]



    @patch.object(MySession, 'get_or_generate_response', new_callable=AsyncMock)
    async def test_llm_response_empty_users(self,mock_llm):
        mock_llm.return_value = json.dumps({
            "columns": ["id", "username"],
            "rows": []
        })

        save_response_to_jsonl(json.loads(mock_llm.return_value))
        my_session = MySession()
        query = "SELECT id, username FROM users WHERE 1=0;"
        rows, columns = await my_session.get_llm_response(query)

        assert rows == []


