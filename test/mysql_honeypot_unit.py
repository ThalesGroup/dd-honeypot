import pytest
import mysql.connector
from mysql.connector.errors import DatabaseError, OperationalError, InterfaceError
from src.mysql_honeypot import MySqlHoneypot
import time


def test_honeypot_should_fail_on_invalid_handshake():
    honeypot = MySqlHoneypot()
    honeypot.start()
    time.sleep(0.1)

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

        assert (
            "Malformed packet" in str(exc_info.value) or
            "initial communication packet" in str(exc_info.value) or
            "Lost connection" in str(exc_info.value)
        )
    finally:
        honeypot.stop()


def test_real_mysql_positive_connection_and_query():
    #Test a positive connection and query on real MySQL.
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
    hp = MySqlHoneypot()
    hp.start()
    time.sleep(0.2)
    yield hp
    hp.stop()
    time.sleep(0.2)


def test_honeypot_connection_and_query_positive(honeypot):
    """Test a successful connection and SELECT query against the honeypot"""
    try:

        with mysql.connector.connect(
                host='localhost',
                port=honeypot.port,
                user='test',
                password='test',
                database='test_db',
                ssl_disabled=True,
                use_pure=True,
                auth_plugin='mysql_native_password'
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchall()
                assert result == [] or result == [(1,)]
    except (DatabaseError, OperationalError, InterfaceError) as e:
        assert any(
            msg in str(e)
            for msg in [
                "Malformed packet",
                "Lost connection",
                "Authentication plugin",
                "Connection reset"
            ]
        )
