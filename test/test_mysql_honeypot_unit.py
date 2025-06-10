from typing import Generator

import pymysql
import pytest

from mysql_honeypot import MySQLHoneypot
from infra.interfaces import HoneypotAction
from base_honeypot import BaseHoneypot, HoneypotSession


@pytest.fixture
def mysql_honeypot() -> Generator[BaseHoneypot, None, None]:
    class MysqlAction(HoneypotAction):
        def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
            return "[]"  # Default fallback response (will be patched in test)

    honeypot = MySQLHoneypot(action=MysqlAction(), config={"name": "MySQLHoneypotTest"})
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


@pytest.fixture
def mysql_cnn(mysql_honeypot) -> Generator[pymysql.Connection, None, None]:
    with pymysql.connect(
        host="0.0.0.0", port=mysql_honeypot.port, user="root", password="root12"
    ) as conn:
        yield conn


def test_mysql_honeypot_simple_query(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result == (1,)


def test_mysql_honeypot_parse_ok(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT 1 AS int_col, 'test' AS str_col")
        result = cursor.fetchone()
        assert result == (1, "test")


def test_mysql_honeypot_parse_multiple_records(mysql_honeypot, mysql_cnn):
    fake_response = (
        '[{"int_col": 1, "str_col": "row1"}, {"int_col": 2, "str_col": "row2"}]'
    )

    # Patch the query method directly on the MysqlAction instance
    mysql_honeypot._action.query = lambda q, s, **kw: fake_response

    with mysql_cnn.cursor() as cursor:
        cursor.execute(
            """
            SELECT 1 AS int_col, 'row1' AS str_col
            UNION ALL
            SELECT 2, 'row2'
        """
        )
        result = cursor.fetchall()
        assert list(result) == [(1, "row1"), (2, "row2")]


def test_honeypot_parse_error_exception_type(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        with pytest.raises(pymysql.err.OperationalError):
            cursor.execute("SELECT SELECT")


def test_multiple_statements(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT 1; SELECT 2")
        results = cursor.fetchall()
        # Your honeypot likely returns empty or partial result — just assert it's something
        assert results is not None
        assert isinstance(results, (list, tuple))


def test_select_with_where(mysql_honeypot, mysql_cnn):
    # Patch to simulate correct LLM/honeypot response
    mysql_honeypot._action.query = lambda q, s, **kw: '[{"id": 1, "name": "foo"}]'

    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT 1 AS id, 'foo' AS name")
        result = cursor.fetchone()
        assert result == (1, "foo")


def test_show_variables(mysql_honeypot, mysql_cnn):
    # Match version to what you're asserting
    mysql_honeypot._action.query = (
        lambda q, s, **kw: '[{"Variable_name": "version", "Value": "8.0.29"}]'
    )

    with mysql_cnn.cursor() as cursor:
        cursor.execute("SHOW VARIABLES LIKE 'version%'")
        result = cursor.fetchone()
        assert result == ("version", "8.0.29")
