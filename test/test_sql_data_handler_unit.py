import pytest
from pathlib import Path

from infra.interfaces import HoneypotAction
from sql_data_handler import SqlDataHandler


@pytest.fixture()
def sql_data_handler() -> HoneypotAction:
    data_file = str(
        Path(__file__).parent.parent / "test" / "honeypots" / "mysql" / "data.jsonl"
    )
    system_prompt = [
        "You are a MySQL server. Answer queries as if you were a real MySQL DB."
    ]
    model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    return SqlDataHandler(
        data_file=data_file,
        system_prompt=system_prompt,
        model_id=model_id,
    )


def test_parse_ok(sql_data_handler):
    session = sql_data_handler.connect({})
    assert sql_data_handler.query("SELECT 1", session) is None


def test_parse_error(sql_data_handler):
    session = sql_data_handler.connect({})
    error_msg = sql_data_handler.query("SELECT * FROM", session)  # Missing table name
    assert error_msg is not None
    assert "MySQL Syntax Error" in error_msg
