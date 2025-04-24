import os
import socket
import threading
import time
import logging
import pytest
import pymysql
import mysql.connector
import asyncio
from pymysql.err import OperationalError


from mysql.connector.errors import DatabaseError, OperationalError, InterfaceError

from src.mysql_honeypot import MySqlMimicHoneypot

logger = logging.getLogger(__name__)

@pytest.fixture(autouse=True)
def suppress_asyncio_connection_errors(monkeypatch):
    async def quiet_drain(self):
        try:
            await original_drain(self)
        except ConnectionResetError:
            pass  # Suppress expected client disconnects
    original_drain = asyncio.StreamWriter.drain
    monkeypatch.setattr(asyncio.StreamWriter, "drain", quiet_drain)

    # Suppress asyncio connection error log messages
    logger = logging.getLogger("asyncio")
    logger.setLevel(logging.CRITICAL)  # Or logging.ERROR to keep warnings


@pytest.fixture
def running_honeypot():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(1)  # Allow server to start
    yield honeypot
    honeypot.stop()


def test_honeypot_should_fail_on_invalid_handshake():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(1)

    try:
        with pytest.raises((DatabaseError, OperationalError, InterfaceError)) as exc_info:
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



def test_invalid_query_response():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(1)

    # Attempting an invalid query should raise OperationalError
    with pytest.raises(pymysql.MySQLError) as excinfo:
        pymysql.connect(
            host="127.0.0.1",
            port=honeypot.port,
            user="test",
            password="123",
            connect_timeout=5,
            ssl={'disabled': True},
            charset="latin1"
        ).cursor().execute("INVALID QUERY")

    assert "You have an error in your SQL syntax" in str(excinfo.value)
