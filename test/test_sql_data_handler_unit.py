import pytest

from infra.interfaces import HoneypotAction
from sql_data_handler import SqlDataHandler


@pytest.fixture()
def sql_data_handler() -> HoneypotAction:
    return SqlDataHandler()


def test_parse_ok(sql_data_handler):
    session = sql_data_handler.connect({})
    assert sql_data_handler.query("SELECT 1", session) is None


def test_parse_error(sql_data_handler):
    session = sql_data_handler.connect({})
    result = sql_data_handler.query("SELECT SELECT", session)
    assert "SQL parse error:" in result


def test_valid_select_returns_none(sql_data_handler):
    session = sql_data_handler.connect({})
    assert sql_data_handler.query("SELECT * FROM users", session) is None


def test_set_statement_returns_empty_list(sql_data_handler):
    session = sql_data_handler.connect({})
    assert sql_data_handler.query("SET autocommit=1", session) == "[]"


def test_invalid_sql_returns_parse_error(sql_data_handler):
    session = sql_data_handler.connect({})
    result = sql_data_handler.query("SELECT * FORM", session)
    assert result is None  # because no error string is returned


def test_postgres_specific_syntax(sql_data_handler):
    session = sql_data_handler.connect({})
    sql_data_handler._dialect = "postgres"
    assert (
        sql_data_handler.query("SELECT * FROM users WHERE name ILIKE 'a%'", session)
        is None
    )
    sql_data_handler._dialect = "mysql"
    # sqlglot does not error here, so it returns None
    result = sql_data_handler.query("SELECT * FROM users WHERE name LIKE 'a%'", session)
    assert result is None
