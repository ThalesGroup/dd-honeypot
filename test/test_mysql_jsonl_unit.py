import json
import os
import tempfile
from pathlib import Path
from typing import Generator

import pymysql
import pytest

from base_honeypot import BaseHoneypot
from src.mysql_honeypot import MySQLHoneypot
from infra.chain_honeypot_action import ChainedHoneypotAction
from infra.data_handler import DataHandler
from sql_data_handler import SqlDataHandler


def _get_jsonl_path() -> Path:
    return Path(__file__).parents[1] / "test" / "mysql_cases.jsonl"


def _get_jsonl_tests() -> list[dict]:
    return [
        json.loads(line)
        for line in _get_jsonl_path().read_text().splitlines()
        if line.strip()
    ]


@pytest.fixture(scope="module")
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


@pytest.fixture(scope="module")
def mysql_cnn(mysql_honeypot):
    with pymysql.connect(
        host="127.0.0.1", port=mysql_honeypot.port, user="root", password="root12"
    ) as conn:
        yield conn


@pytest.mark.parametrize("test_case", _get_jsonl_tests(), ids=lambda t: t["name"])
def test_mysql_jsonl_case(test_case, mysql_cnn):
    sqls = (
        test_case["sql"] if isinstance(test_case["sql"], list) else [test_case["sql"]]
    )
    expected_data = test_case.get("data")
    expected_errors = test_case.get("errors")

    def maybe_parse(val):
        if isinstance(val, str):
            try:
                return json.loads(val)
            except Exception:
                return val
        return val

    def normalize_block(block):
        return [[maybe_parse(col) for col in row] for row in block]

    try:
        collected_data = []
        with mysql_cnn.cursor() as cursor:
            for query in sqls:
                cursor.execute(query)
                rows = cursor.fetchall()
                collected_data.append([list(row) for row in rows])

        # Remove empty SET/USE results etc.
        cleaned = [rows for rows in collected_data if rows]

        # Normalize
        normalized = [normalize_block(rows) for rows in cleaned]

        # Match structure based on expected
        if expected_data is not None and isinstance(expected_data, list):
            is_single_query = (
                isinstance(test_case["sql"], str) or len(test_case["sql"]) == 1
            )
            if (
                is_single_query
                and len(normalized) == 1
                and all(
                    not isinstance(r, list)
                    or isinstance(r[0], (str, int, float, type(None), dict, bool))
                    for r in expected_data
                )
            ):
                # Only flatten if truly single-statement
                actual = normalized[0]
            else:
                actual = normalized
        else:
            actual = normalized

        # Slice extra rows if honeypot returns more (e.g., version_comment)
        if expected_data and isinstance(expected_data, list):
            if isinstance(actual, list):
                actual = actual[: len(expected_data)]

        assert (
            expected_errors is None
        ), f"Expected error {expected_errors}, got: {actual}"
        assert (
            actual == expected_data
        ), f"{test_case['name']} failed:\nExpected: {expected_data}\nGot: {actual}"

    except Exception as e:
        if expected_errors:
            assert any(
                err in str(e) for err in expected_errors
            ), f"Unexpected error in {test_case['name']}: {e}"
        else:
            pytest.fail(f"Unexpected error in {test_case['name']}: {e}")
