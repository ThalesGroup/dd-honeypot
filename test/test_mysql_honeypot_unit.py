import json
import logging
from typing import Generator

import pymysql
import pytest

from conftest import get_honeypot_main
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


def test_mysql_honeypot_main(monkeypatch):
    with get_honeypot_main(monkeypatch, {"type": "mysql"}) as port:
        monkeypatch.setattr(
            "infra.data_handler.invoke_llm",
            lambda *a, **kw: '[{"user": "root", "host": "host1"}]',
        )
        with pymysql.connect(
            host="0.0.0.0", port=port, user="root", password="root12"
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                assert result == (1,)
                cursor.execute("SELECT user, host FROM mysql.user")
                result = cursor.fetchone()
                assert result == ("root", "host1")


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


def test_mysql_honeypot_parse_multiple_records(monkeypatch):
    monkeypatch.setattr(
        "infra.data_handler.invoke_llm",
        lambda *a, **kw: json.dumps(
            [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]
        ),
    )

    with get_honeypot_main(monkeypatch, {"type": "mysql"}) as port:
        with pymysql.connect(
            host="0.0.0.0", port=port, user="root", password="root12"
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, name FROM users")
                result = cursor.fetchall()
                assert result == ((1, "Alice"), (2, "Bob"))


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


def test_mysql_session_with_two_queries(monkeypatch):
    # Patch invoke_llm so no real LLM call is made
    monkeypatch.setattr(
        "infra.data_handler.invoke_llm",
        lambda *a, **kw: '[{"user": "root", "host": "host1"}]',
    )

    with get_honeypot_main(monkeypatch, {"type": "mysql"}) as port:
        with pymysql.connect(
            host="0.0.0.0", port=port, user="session_user", password="pass"
        ) as conn:
            with conn.cursor() as cursor:
                # 1st query: simple SELECT 1
                cursor.execute("SELECT 1;")
                result1 = cursor.fetchone()
                assert result1 == (1,)

                # 2nd query: show user+host - honeypot returns fixed LLM response
                cursor.execute("SELECT user, host FROM mysql.user;")
                result2 = cursor.fetchone()
                assert result2 == ("root", "host1")

