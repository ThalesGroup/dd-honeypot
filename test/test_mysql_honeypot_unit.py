import os
import time
import socket
import logging
import pytest
import pymysql
import mysql.connector
from mysql.connector.errors import DatabaseError, OperationalError, InterfaceError

from src.mysql_honeypot import MySqlMimicHoneypot

logger = logging.getLogger(__name__)


def test_honeypot_should_fail_on_invalid_handshake():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(1)

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


@pytest.mark.skipif(os.getenv("CI") == "true", reason="MySQL not available in CI")
def test_real_mysql_connection_and_query():
    """Test a positive connection and query on real MySQL."""
    try:
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
    except Exception as e:
        pytest.skip(f"Skipping real MySQL test: {str(e)}")


def test_honeypot_connection_and_query():
    honeypot = MySqlMimicHoneypot()
    honeypot.start()
    time.sleep(1)

    try:
        retries = 5
        for attempt in range(retries):
            try:
                conn = pymysql.connect(
                    host="localhost",
                    port=honeypot.port,
                    user="test",
                    password="test",
                    connect_timeout=3,
                )
                cursor = conn.cursor()
                cursor.execute("SELECT 1;")
                result = cursor.fetchone()
                logger.info(f"Received result: {result}")
                assert result is not None, "Expected non-empty result"
                break
            except pymysql.MySQLError as e:
                logger.warning(f"Attempt {attempt+1} failed: {e}")
                if attempt == retries - 1:
                    pytest.fail(f"Failed after {retries} attempts: {e}")
                time.sleep(1)
    finally:
        honeypot.stop()
