from typing import Generator

import pymysql
import pytest

from base_honeypot import BaseHoneypot, HoneypotSession
from infra.chain_honeypot_action import ChainedHoneypotAction
from infra.interfaces import HoneypotAction
from mysql_honeypot import MySQLHoneypot
from sql_data_handler import SqlDataHandler


@pytest.fixture
def mysql_honeypot() -> Generator[BaseHoneypot, None, None]:
    class MysqlAction(HoneypotAction):
        def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
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


def test_mysql_honeypot_parse_ok(mysql_cnn):
    with mysql_cnn.cursor() as cursor:
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result == (1,), f"Expected (1,), got {result}"


def test_mysql_honeypot_parse_error(mysql_cnn):
    with pytest.raises(pymysql.err.OperationalError):  # Change here
        with mysql_cnn.cursor() as cursor:
            cursor.execute("SELECT SELECT")
