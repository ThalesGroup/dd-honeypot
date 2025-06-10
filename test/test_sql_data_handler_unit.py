import pytest
from sql_data_handler import SqlDataHandler


@pytest.fixture()
def sql_data_handler():
    return SqlDataHandler()


def test_parse_ok(sql_data_handler):
    session = sql_data_handler.connect({})
    result = sql_data_handler.query("SELECT 1", session)
    assert result is None


def test_valid_select_returns_none(sql_data_handler):
    session = sql_data_handler.connect({})
    result = sql_data_handler.query("SELECT * FROM users", session)
    assert result is None


def test_parse_error(sql_data_handler):
    session = sql_data_handler.connect({})
    result = sql_data_handler.query("SELECT SELECT", session)
    assert isinstance(result, str)
    assert result.startswith('[{"error": "SQL parse error:')
    assert "Unexpected token" in result or "Invalid expression" in result

def test_invalid_sql_returns_none(sql_data_handler):
    session = sql_data_handler.connect({})
    result = sql_data_handler.query("SELECT * FORM", session)
    assert result is None


def test_set_statement_returns_empty_list(sql_data_handler):
    session = sql_data_handler.connect({})
    result = sql_data_handler.query("SET autocommit=1", session)
    assert result == "[]"


def test_postgres_specific_syntax(sql_data_handler):
    session = sql_data_handler.connect({})
    sql_data_handler._dialect = "postgres"
    result = sql_data_handler.query(
        "SELECT * FROM users WHERE name ILIKE 'a%'", session
    )
    assert result is None

    sql_data_handler._dialect = "mysql"
    result = sql_data_handler.query("SELECT * FROM users WHERE name LIKE 'a%'", session)
    assert result is None
