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
