import pytest
import mysql.connector
from mysql.connector.errors import DatabaseError, OperationalError, InterfaceError
from mysql_mimic import errors

from src.mysql_honeypot import MySqlMimicHoneypot
import time
import socket



def test_honeypot_should_fail_on_invalid_handshake():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(0.2)

    try:
        with pytest.raises((DatabaseError, OperationalError, InterfaceError)) as exc_info:
            with mysql.connector.connect(
                host="localhost",
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
                "Malformed packet"
            ]
        ), f"Unexpected error message: {msg}"

    finally:
        honeypot.stop()


def test_real_mysql_connection_and_query():
    """Test a positive connection and query on real MySQL."""
    with mysql.connector.connect(
        host="localhost",
        port=3306,
        user="test",
        password="test",
        database="test_db"
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1;")
            result = cursor.fetchone()
            assert result == (1,), f"Expected (1,), got {result}"


@pytest.fixture
def honeypot():
    """Fixture to start the MySQL-Mimic honeypot."""
    honeypot_instance = MySqlMimicHoneypot()
    honeypot_instance.start()
    time.sleep(5)  # Ensure honeypot has time to initialize
    yield honeypot_instance
    honeypot_instance.stop()


def test_honeypot_connection_and_query(honeypot):
    """Test a successful connection and SELECT query against the MySQL-Mimic honeypot."""

    retries = 2
    delay = 6  # Increase delay for retries to give the honeypot more time

    for attempt in range(retries):
        try:
            # Connect to the honeypot using localhost
            with mysql.connector.connect(
                    host="localhost",  # Use localhost for connection
                    port=honeypot.port,
                    user="root",
                    password="",  # Empty password as per the configuration
                    database="test_db",  # Ensure the database exists
                    connection_timeout=120,  # Increase connection timeout to 120 seconds
                    read_timeout=120,  # Increase read timeout to 120 seconds
                    ssl_disabled=True,
                    auth_plugin="mysql_native_password",
                    use_pure=True,
                    unix_socket=None
            ) as conn:
                # Successful connection, now test query
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                assert result == (1,)  # Verify the result is (1,)
                break  # If successful, break the retry loop

        except (mysql.connector.errors.DatabaseError, mysql.connector.errors.InterfaceError) as err:
            print(f"Attempt {attempt + 1} failed: {err}")
            if attempt == retries - 1:
                raise err  # If final attempt fails, raise the error again
            time.sleep(delay)  # Wait before retrying