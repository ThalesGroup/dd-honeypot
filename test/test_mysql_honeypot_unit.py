from typing import Generator

import pymysql
import pytest

from base_honeypot import BaseHoneypot, HoneypotSession
from conftest import get_honeypot_main
from infra.chain_honeypot_action import ChainedHoneypotAction
from infra.interfaces import HoneypotAction
from mysql_honeypot import MySQLHoneypot
from sql_data_handler import SqlDataHandler


@pytest.fixture
def mysql_honeypot() -> Generator[BaseHoneypot, None, None]:
    class MysqlAction(HoneypotAction):
        def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
            if "UNION ALL" in query:
                return '[{"int_col": 1, "str_col": "row1"}, {"int_col": 2, "str_col": "row2"}]'
            # fallback
            return '[{"response": "ok"}]'

    action = ChainedHoneypotAction(MysqlAction(), SqlDataHandler(dialect="mysql"))
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
    try:
        with mysql_cnn.cursor() as cursor:
            try:
                cursor.execute("SELECT SELECT")
                pytest.fail("Expected OperationalError, but none was raised")
            except Exception as e:
                assert isinstance(e, pymysql.err.OperationalError)
    except pymysql.MySQLError as e:
        pytest.fail(f"Honeypot connection failed: {e}")


def test_real_mysql_parse_error():
    try:
        with pymysql.connect(
            host="0.0.0.0",
            port=3306,
            user="root",
            password="",
        ) as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute("SELECT SELECT")
                    pytest.fail("Expected ProgrammingError, but none was raised")
                except Exception as e:
                    assert isinstance(e, pymysql.err.ProgrammingError)
    except pymysql.MySQLError as e:
        pytest.fail(f"Failed to connect to real MySQL: {e}")


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


def test_multiple_statements(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        try:
            cursor.execute("SELECT 1; SELECT 2")
            results = cursor.fetchall()
            assert len(results) > 0  # If execution succeeds, check at least one result
        except (pymysql.err.ProgrammingError, pymysql.err.InternalError) as e:
            assert (
                "You have an error in your SQL syntax" in str()
                or "not allowed to execute multiple statements" in str(e)
            )


def test_mysql_honeypot_parse_multiple_records(mysql_cnn):
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


def test_select_with_where(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT 1 AS id, 'foo' AS name WHERE 1=1")
        result = cursor.fetchone()
        assert result == ("ok",)


def test_show_variables(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SHOW VARIABLES LIKE 'version%'")
        result = cursor.fetchone()
        assert result is not None and isinstance(result, tuple)


def test_mysql_honeypot_query():
    conn = pymysql.connect(
        host="54.147.241.42",
        port=3306,
        user="root",
        password="",
        autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1;")
            result = cursor.fetchall()
            assert result == [{"1": 1}]
    finally:
        conn.close()
