import json
import tempfile
from typing import Generator

import pymysql
import pytest

from conftest import get_honeypot_main
from infra.chain_honeypot_action import ChainedHoneypotAction
from infra.data_handler import DataHandler
from mysql_honeypot import MySQLHoneypot
from infra.interfaces import HoneypotAction
from base_honeypot import BaseHoneypot, HoneypotSession
from sql_data_handler import SqlDataHandler


@pytest.fixture
def mysql_honeypot() -> Generator[BaseHoneypot, None, None]:
    with tempfile.NamedTemporaryFile() as f:
        action = ChainedHoneypotAction(
            DataHandler(f.name, "You are MYSQL honeypot", "no model"),
            SqlDataHandler(dialect="mysql"),
        )
        honeypot = MySQLHoneypot(action=action, config={"name": "MySQLHoneypotTest"})
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


def test_honeypot_parse_error_exception_type(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        with pytest.raises(pymysql.err.OperationalError):
            cursor.execute("SELECT SELECT")


def test_multiple_statements(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT 1; SELECT 2")
        results = cursor.fetchall()
        assert results is not None
        assert isinstance(results, (list, tuple))


def test_select_with_where(monkeypatch, mysql_cnn):
    monkeypatch.setattr(
        "infra.data_handler.DataHandler.query",
        lambda self, query, session, **kw: '[{"id": 1, "name": "foo"}]',
    )
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT id, name FROM users WHERE name = 'foo'")
        result = cursor.fetchone()
        assert result == (1, "foo")


def test_show_variables(monkeypatch, mysql_cnn):
    monkeypatch.setattr(
        "infra.data_handler.DataHandler.query",
        lambda self, query, session, **kw: '[{"Variable_name": "version", "Value": "8.0.29"}]',
    )
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SHOW VARIABLES LIKE 'version%'")
        result = cursor.fetchone()
        assert result == ("version", "8.0.29")


def test_mysql_fallback_multiple_rows(monkeypatch, mysql_cnn):
    monkeypatch.setattr(
        "infra.data_handler.invoke_llm",
        lambda *_args, **_kwargs: json.dumps(
            [
                {"id": 1, "name": "user_a"},
                {"id": 2, "name": "user_b"},
            ]
        ),
    )
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT id, name FROM trigger_fallback")
        result = cursor.fetchall()
        assert result == ((1, "user_a"), (2, "user_b"))


def test_mysql_multiple_statements_same_session(monkeypatch, mysql_cnn):
    monkeypatch.setattr(
        "infra.data_handler.DataHandler.query",
        lambda self, query, session, **kw: (
            json.dumps([{"dummy": 42}])
            if "SELECT 42" in query
            else json.dumps([{"user": "admin", "host": "localhost"}])
        ),
    )

    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT 42 as dummy")
        result1 = cursor.fetchone()
        assert result1 == (42,)

        cursor.execute("SELECT user, host FROM mysql.user")
        result2 = cursor.fetchone()
        assert result2 == ("admin", "localhost")
