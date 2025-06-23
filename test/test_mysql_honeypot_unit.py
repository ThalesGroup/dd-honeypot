import json


import tempfile
from typing import Generator
import os

import pymysql
import pytest

from conftest import get_honeypot_main
from infra.chain_honeypot_action import ChainedHoneypotAction
from infra.data_handler import DataHandler
from src.mysql_honeypot import MySQLHoneypot
from base_honeypot import BaseHoneypot
from sql_data_handler import SqlDataHandler


@pytest.fixture
def mysql_honeypot() -> Generator[BaseHoneypot, None, None]:
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    with tempfile.NamedTemporaryFile() as f:
        action = ChainedHoneypotAction(
            DataHandler(
                f.name,
                "You are MYSQL honeypot.",
                "anthropic.claude-3-sonnet-20240229-v1:0",
            ),
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
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
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


def test_mysql_session_variable(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SET @my_var = 123")
        cursor.execute("SELECT @my_var")
        result = cursor.fetchone()
        assert result == (123,)


def test_select_missing_variable(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT @missing_var")
        result = cursor.fetchone()
        assert result == (None,)  # Expecting NULL for unset variable


def test_var_json_object(mysql_cnn):
    json_obj = '{"key1": "value1", "key2": 42}'
    set_query = f"SET @myvar = {json_obj}"

    with mysql_cnn.cursor() as cursor:
        cursor.execute(set_query)
        result = cursor.fetchall()
        assert result == []

    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT @myvar")
        result = cursor.fetchall()
        # result is ((json_str,),)
        returned_json_str = result[0][0]
        returned_obj = json.loads(returned_json_str)
        expected_obj = json.loads(json_obj)
        assert returned_obj == expected_obj


async def test_set_and_select_null(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SET @x = NULL")
        cursor.execute("SELECT @x")
        result = cursor.fetchone()
        assert result[0] is None


async def test_set_invalid_json_fallbacks(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SET @x = not_json")
        cursor.execute("SELECT @x")
        assert cursor.fetchone()[0] == "not_json"

        cursor.execute("SET @y = quoted str")
        cursor.execute("SELECT @y")
        assert cursor.fetchone()[0] == "quoted str"


def test_show_databases(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SHOW DATABASES")
        result = cursor.fetchall()
        assert result  # or assert something about the format


def test_commit_command(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("COMMIT")
        result = cursor.fetchall()
        assert result == []


def test_use_database(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("USE RECOVER_YOUR_DATA")
        result = cursor.fetchall()
        assert result == []


def test_set_json_object(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute('SET @data = JSON_OBJECT("x", 42)')
        cursor.execute("SELECT @data")
        result = cursor.fetchone()
        assert result[0] == 'JSON_OBJECT("x", 42)'  # No evaluation happens in honeypot


def test_select_version(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT VERSION()")
        result = cursor.fetchone()
        assert result is not None


def test_select_current_date(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT CURRENT_DATE")
        result = cursor.fetchone()
        assert result is not None


def test_select_quoted_dollar_string(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT '$$'")
        result = cursor.fetchone()
        assert result == ("$$",)
