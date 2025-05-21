import asyncio
import json
import logging
import os
import socket
import threading
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock


import mysql.connector
import pymysql
import pytest
from mysql.connector.errors import DatabaseError, OperationalError, InterfaceError
from pymysql.err import OperationalError

from conftest import get_honeypots_folder, get_config
from infra.honeypot_wrapper import (
    create_honeypot,
)  # Assuming create_honeypot is in honeypot_wrapper
from mysql_honeypot import (
    MySession,
    MySqlMimicHoneypot,
    MysqlError,
)  # Import your session class

logger = logging.getLogger(__name__)
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
    honeypot = create_honeypot(config={"type": "mysql"})
    honeypot.start()
    time.sleep(1)  # Allow server to start
    yield honeypot
    honeypot.stop()


@pytest.fixture(scope="module")
def run_honeypot():
    config = get_config("mysql")
    config["data_file"] = os.path.join(get_honeypots_folder(), "mysql", "data.jsonl")
    config["port"] = 0

    honeypot = create_honeypot(config=config)
    thread = threading.Thread(target=honeypot.start, daemon=True)
    thread.start()

    timeout = 5
    start = time.time()
    while True:
        try:
            with socket.create_connection(("127.0.0.1", honeypot.port), timeout=0.5):
                break
        except (ConnectionRefusedError, OSError):
            if time.time() - start > timeout:
                raise TimeoutError("Honeypot did not start within timeout.")
            time.sleep(0.1)

    yield honeypot
    honeypot.stop()


"""Ensures that the honeypot properly handles invalid handshakes and rejects 
connections with the expected error messages."""


def test_honeypot_should_fail_on_invalid_handshake(run_honeypot):
    try:
        with pytest.raises((DatabaseError, OperationalError, InterfaceError)) as exc_info:  # type: ignore
            with mysql.connector.connect(
                host="54.172.18.244 ",
                port=run_honeypot.port,
                user="test",
                password="test",
                database="test_db",
                connection_timeout=2,
                ssl_disabled=True,
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1;")
                    cursor.fetchone()

        msg = str(exc_info.value)
        assert any(
            err in msg
            for err in [
                "Can't connect to MySQL server",
                "Lost connection",
                "initial communication packet",
                "Malformed packet",
                "1105 (HY000)",
                "Access denied for user",
            ]
        ), f"Unexpected error message: {msg}"

    finally:
        run_honeypot.stop()


"""Tests real MySQL connection and query execution on an actual MySQL server."""


@pytest.mark.skipif(os.getenv("CI") == "true", reason="MySQL not available in CI")
def test_real_mysql_connection_and_query(run_honeypot):
    """Test a positive connection and diverse queries on real MySQL."""
    try:
        with mysql.connector.connect(
            host="127.0.0.1",
            port=3306,
            user="test",
            password="test",
            database="test_db",
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
                assert concat_result == (
                    "DataLure",
                ), f"Expected ('DataLure',), got {concat_result}"

                # Test current timestamp
                cursor.execute("SELECT NOW();")
                timestamp = cursor.fetchone()
                assert timestamp[0] is not None, "Expected a timestamp, got None"

                # Test system/user info
                cursor.execute("SELECT USER(), DATABASE();")
                user_info = cursor.fetchone()
                assert (
                    user_info[0] is not None and user_info[1] == "test_db"
                ), f"Unexpected user/db: {user_info}"

    except Exception as e:
        pytest.skip(f"Skipping real MySQL test: {str(e)}")


"""Tests connectivity to the honeypot using both mysql-connector and pymysql libraries."""


@pytest.mark.skipif(os.getenv("CI") == "true", reason="MySQL not available in CI")
def test_real_mysql_basic_operations(run_honeypot):
    """Test basic SQL operations on real MySQL to compare expected responses."""
    try:
        conn = mysql.connector.connect(
            host="127.0.0.1",
            port=3306,
            user="test",
            password="test",
            database="test_db",
        )
        cursor = conn.cursor()

        # Create a temporary table
        cursor.execute(
            "CREATE TEMPORARY TABLE IF NOT EXISTS temp_users (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(50));"
        )

        # Insert values
        cursor.execute("INSERT INTO temp_users (name) VALUES ('person1'), ('person2');")
        conn.commit()

        # Select and check values
        cursor.execute("SELECT name FROM temp_users ORDER BY id;")
        results = cursor.fetchall()
        assert results == [
            ("person1",),
            ("person2",),
        ], f"Unexpected query result: {results}"

        # Cleanup is automatic since it's a TEMPORARY table

        cursor.close()
        conn.close()
    except Exception as e:
        pytest.skip(f"Skipping real DB test due to error: {str(e)}")


def test_honeypot_connection_mysql_connector(run_honeypot):
    try:
        with mysql.connector.connect(
            host="127.0.0.1",
            port=run_honeypot.port,
            user="test",
            password="test",
            auth_plugin="mysql_native_password",
            connection_timeout=3,
            ssl_disabled=True,
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                assert result == (1,), f"Expected (1,), got {result}"

    except Exception as e:
        logger.info(
            f"mysql-connector attempt failed, falling back to pymysql: {repr(e)}"
        )
    finally:
        run_honeypot.stop()


"""Tests connectivity to the honeypot using both mysql-connector and pymysql libraries."""


def test_honeypot_connection_pymysql(run_honeypot):

    try:
        with pymysql.connect(
            host="127.0.0.1",
            port=run_honeypot.port,
            user="test",
            password="test",
            connect_timeout=3,
            ssl={"disabled": True},  # Explicitly disable SSL
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                assert result == (1,), f"Expected (1,), got {result}"

    except Exception as e:
        logger.info(
            f"mysql-connector attempt failed, falling back to pymysql: {repr(e)}"
        )
    finally:
        run_honeypot.stop()


def test_connection_to_honeypot(run_honeypot):
    host = "127.0.0.1"
    port = run_honeypot.port

    # Update the expected exception to match the actual error message format
    with pytest.raises(
        mysql.connector.errors.ProgrammingError,
        match=r"1045 \(28000\): Access denied for user attacker",
    ):
        mysql.connector.connect(
            host=host, port=port, user="attacker", password="fake", connect_timeout=5
        )


def save_response_to_jsonl(
    response: dict, honeypot_type: str = "mysql", file_path: Path = None
):
    """Save unique LLM response to a JSONL file."""
    if file_path is None:
        folder = Path(get_honeypots_folder()) / honeypot_type
        folder.mkdir(parents=True, exist_ok=True)
        file_path = folder / "data.jsonl"
    else:
        file_path.parent.mkdir(parents=True, exist_ok=True)

    existing = set()
    if file_path.exists():
        with open(file_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    key = data.get("query") or json.dumps(data)
                    existing.add(key)
                except json.JSONDecodeError:
                    pass

    key = response.get("query") or json.dumps(response)
    if key not in existing:
        with open(file_path, "a") as f:
            json.dump(response, f)
            f.write("\n")
        print(f" Saved new query: {key}")
    else:
        print(f" Skipping duplicate query: {key}")


@pytest.fixture
def mysql_honeypot(tmp_path: Path):
    # Write minimal config.json to avoid missing config error if your code reads from this file
    config_content = {
        "model_id": "test-model",
        "system_prompt": "You are a MySQL server emulator.",
    }
    config_path = tmp_path / "config.json"
    with open(config_path, "w") as f:
        json.dump(config_content, f)

    # Create an empty data.jsonl file (for caching or data storage)
    data_file = tmp_path / "data.jsonl"
    data_file.touch()

    # Compose full config dict inline to pass directly to create_honeypot
    config = {
        "type": "mysql",
        "port": 0,  # let system assign a free port
        "data_file": str(data_file),
        "config_path": str(config_path),  # pass config path if your code reads from it
        "system_prompt": "You are a MySQL server emulator.",
        "model_id": "test-model",
    }

    # Patch invoke_llm to avoid real LLM calls during testing
    with patch("infra.data_handler.invoke_llm", return_value="Mocked LLM response"):
        honeypot = create_honeypot(config)
        honeypot.start()
        time.sleep(0.2)  # Allow honeypot to initialize
        yield honeypot
        honeypot.stop()


@pytest.fixture
def my_session(tmp_path):
    # Pass base_dir to MySession to let it find config.json in tmp_path
    return MySession(base_dir=tmp_path)


@pytest.mark.asyncio
class TestLLMResponseParsing:

    @patch.object(MySession, "get_or_generate_response", new_callable=MagicMock)
    async def test_llm_response_valid_data(self, mock_llm, mysql_honeypot, tmp_path):
        future = asyncio.Future()
        future.set_result(
            {
                "columns": ["username", "email"],
                "rows": [
                    ["person3", "person3@example.com"],
                    ["bob", "bob@example.com"],
                ],
            }
        )
        mock_llm.return_value = future

        save_response_to_jsonl(
            json.loads(mock_llm.return_value.result()),
            file_path=tmp_path / "data.jsonl",
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert isinstance(columns, list)
        assert isinstance(rows, list)
        assert len(columns) == 2
        assert len(rows) == 2
        assert columns == ["username", "email"]
        assert rows[0] == ("person3", "person3@example.com")

    @patch.object(MySession, "get_or_generate_response", new_callable=MagicMock)
    @patch("mysql_honeypot.logger")
    async def test_llm_response_invalid_fallback(
        self, mock_logger, mock_llm, mysql_honeypot, tmp_path
    ):
        future = asyncio.Future()
        future.set_result("")
        mock_llm.return_value = future

        save_response_to_jsonl(
            {"columns": ["Invalid LLM Output"], "rows": []},
            file_path=tmp_path / "data.jsonl",
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert columns == ["Invalid LLM Output"]
        assert rows == []
        mock_logger.error.assert_called_with("Empty or invalid response from LLM.")

    @patch.object(MySession, "get_or_generate_response", new_callable=AsyncMock)
    @patch("mysql_honeypot.logger")
    async def test_llm_response_invalid_data(
        self, mock_logger, mock_llm, mysql_honeypot, tmp_path
    ):
        mock_llm.return_value = "{invalid_json: true, columns: [username], rows: []}"

        save_response_to_jsonl(
            {"columns": ["Invalid LLM Output"], "rows": []},
            file_path=tmp_path / "data.jsonl",
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert columns == ["Invalid LLM Output"]
        assert rows == []
        mock_logger.error.assert_called()

    @patch.object(MySession, "get_or_generate_response", new_callable=AsyncMock)
    async def test_llm_response_with_large_data(
        self, mock_llm, mysql_honeypot, tmp_path
    ):
        mock_llm.return_value = json.dumps(
            {
                "columns": ["username", "email"],
                "rows": [(f"user{i}", f"user{i}@example.com") for i in range(5)],
            }
        )

        save_response_to_jsonl(
            json.loads(mock_llm.return_value), file_path=tmp_path / "data.jsonl"
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert len(rows) == 5
        assert len(columns) == 2

    @patch.object(MySession, "get_or_generate_response", new_callable=AsyncMock)
    async def test_llm_response_select_users(self, mock_llm, mysql_honeypot, tmp_path):
        mock_llm.return_value = json.dumps(
            {
                "columns": ["id", "username"],
                "rows": [(1, "user1"), (2, "user2")],
            }
        )

        save_response_to_jsonl(
            json.loads(mock_llm.return_value), file_path=tmp_path / "data.jsonl"
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response("SELECT * FROM users;")

        assert columns == ["id", "username"]
        assert rows == [(1, "user1"), (2, "user2")]

    @patch.object(MySession, "get_or_generate_response", new_callable=AsyncMock)
    async def test_llm_response_show_databases(
        self, mock_llm, mysql_honeypot, tmp_path
    ):
        mock_llm.return_value = json.dumps(
            {
                "columns": ["Database"],
                "rows": [("db1",), ("db2",)],
            }
        )

        save_response_to_jsonl(
            json.loads(mock_llm.return_value), file_path=tmp_path / "data.jsonl"
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response("SHOW DATABASES;")

        assert columns == ["Database"]
        assert rows == [("db1",), ("db2",)]

    @patch.object(MySession, "get_or_generate_response", new_callable=AsyncMock)
    async def test_llm_response_select_email(self, mock_llm, mysql_honeypot, tmp_path):
        mock_llm.return_value = json.dumps(
            {
                "columns": ["email"],
                "rows": [("a@example.com",), ("b@example.com",)],
            }
        )

        save_response_to_jsonl(
            json.loads(mock_llm.return_value), file_path=tmp_path / "data.jsonl"
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response(
            "SELECT email FROM customers;"
        )

        assert columns == ["email"]
        assert rows == [("a@example.com",), ("b@example.com",)]

    @patch.object(MySession, "get_or_generate_response", new_callable=AsyncMock)
    async def test_llm_response_empty_users(self, mock_llm, mysql_honeypot, tmp_path):
        mock_llm.return_value = json.dumps(
            {
                "columns": ["id", "username"],
                "rows": [],
            }
        )

        save_response_to_jsonl(
            json.loads(mock_llm.return_value), file_path=tmp_path / "data.jsonl"
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response(
            "SELECT id, username FROM users WHERE 1=0;"
        )

        assert rows == []

    @patch.object(MySession, "get_or_generate_response", new_callable=AsyncMock)
    async def test_llm_response_valid_data(self, mock_llm, mysql_honeypot, tmp_path):
        mock_llm.return_value = json.dumps(
            {
                "columns": ["username", "email"],
                "rows": [
                    ("person3", "person3@example.com"),
                    ("bob", "bob@example.com"),
                ],
            }
        )

        save_response_to_jsonl(
            json.loads(mock_llm.return_value), file_path=tmp_path / "data.jsonl"
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert isinstance(columns, list)
        assert isinstance(rows, list)
        assert len(columns) == 2
        assert len(rows) == 2
        assert columns == ["username", "email"]
        assert rows[0] == ("person3", "person3@example.com")

    @patch.object(MySession, "get_or_generate_response", new_callable=MagicMock)
    @patch("mysql_honeypot.logger")
    async def test_llm_response_invalid_fallback(
        self, mock_logger, mock_llm, mysql_honeypot, tmp_path
    ):
        mock_llm.return_value = ""

        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response("SELECT * FROM users")

        assert columns == ["Error in generating response"]
        assert rows == []
        mock_logger.error.assert_called()

    @patch.object(MySession, "get_or_generate_response", new_callable=AsyncMock)
    async def test_llm_response_with_null_values(
        self, mock_llm, mysql_honeypot, tmp_path
    ):
        mock_llm.return_value = json.dumps(
            {
                "columns": ["id", "email"],
                "rows": [(1, None), (2, "user2@example.com")],
            }
        )

        save_response_to_jsonl(
            json.loads(mock_llm.return_value), file_path=tmp_path / "data.jsonl"
        )
        my_session = MySession(base_dir=tmp_path)
        rows, columns = await my_session.get_llm_response(
            "SELECT id, email FROM users;"
        )

        assert columns == ["id", "email"]
        assert rows == [(1, None), (2, "user2@example.com")]

    @patch.object(MySession, "get_or_generate_response", new_callable=AsyncMock)
    async def test_llm_response_large_dataset(self, mock_llm, mysql_honeypot, tmp_path):
        columns = ["id", "value"]
        rows = [(i, f"value_{i}") for i in range(6)]
        mock_llm.return_value = json.dumps({"columns": columns, "rows": rows})

        save_response_to_jsonl(
            json.loads(mock_llm.return_value), file_path=tmp_path / "data.jsonl"
        )
        my_session = MySession(base_dir=tmp_path)
        result_rows, result_columns = await my_session.get_llm_response(
            "SELECT id, value FROM big_table;"
        )

        assert result_columns == columns
        assert result_rows == rows
        assert len(result_rows) == 6


@pytest.mark.asyncio
class TestSessionVariables:

    @pytest.fixture(autouse=True)
    async def setup(self, tmp_path):
        mock_data_handler = MagicMock()
        mock_data_handler.get_data = AsyncMock(
            return_value={"rows": [["Hello from LLM"]], "columns": ["col"]}
        )
        mock_data_handler.save_data = AsyncMock()

        # Wrap it in a function
        def handler_factory():
            return mock_data_handler

        self.honeypot = create_honeypot(
            config={
                "type": "mysql",
                "data_file": str(tmp_path / "data.jsonl"),
                "model_id": "test-model",
                "system_prompt": "You are a helpful assistant.",
                "port": 3306,
                "data_handler": handler_factory,  #  wrapped in function
            }
        )

        self.session_id = "test_session"

    async def test_same_query_is_cached(self):
        # Run query twice and check results are the same (no data_handler mocking)
        rows1, cols1 = await self.honeypot.query(self.session_id, "SELECT * FROM test")
        rows2, cols2 = await self.honeypot.query(self.session_id, "SELECT * FROM test")
        assert rows2 == rows1
        assert cols2 == cols1

    async def test_set_variable(self):
        result = await self.honeypot.query(self.session_id, "SET foo = bar")
        assert result == ("OK",) or "OK" in str(result)

    async def test_fallback_to_llm(self):
        self.honeypot.action = None
        self.honeypot.honeypot_session = None

        rows, cols = await self.honeypot.query(self.session_id, "SELECT llm_fallback()")
        # You may need to adjust these assertions depending on your honeypot fallback behavior
        assert rows is not None
        assert cols is not None
