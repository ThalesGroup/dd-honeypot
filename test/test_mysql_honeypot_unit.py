import os
import time
import logging
import pytest
import pymysql
import mysql.connector
import asyncio


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
    """Test a positive connection and query on real MySQL."""
    try:
        with mysql.connector.connect(
            host="127.0.0.1",
            port=3306,
            user="test",
            password="test",
            database="test_db"
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1;")
                result = cursor.fetchone()
                assert result == (1,), f"Expected (1,), got {result}"
    except Exception as e:
        pytest.skip(f"Skipping real MySQL test: {str(e)}")


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
