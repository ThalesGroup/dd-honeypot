import os
import tempfile
import pytest
from typing import Generator

from buenavista.postgres import BVContext
from buenavista.core import QueryResult, BVType

from base_honeypot import BaseHoneypot
from postgresql_honeypot import PostgresHoneypot
from infra.data_handler import DataHandler
from sql_data_handler import SqlDataHandler
from infra.chain_honeypot_action import ChainedHoneypotAction


@pytest.fixture
def postgres_honeypot() -> Generator[BaseHoneypot, None, None]:
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    with tempfile.NamedTemporaryFile() as f:
        action = ChainedHoneypotAction(
            DataHandler(
                f.name,
                "You are a PostgreSQL honeypot.",
                "anthropic.claude-3-sonnet-20240229-v1:0",
            ),
            SqlDataHandler(dialect="postgresql"),
        )
        honeypot = PostgresHoneypot(
            action=action, config={"name": "PostgresHoneypotTest"}
        )
        try:
            honeypot.start()
            yield honeypot
        finally:
            honeypot.stop()


@pytest.fixture
def dummy_ctx():
    class DummyQueryResult(QueryResult):
        def __init__(self, select=True):
            super().__init__()
            if select:
                self.columns = [(b"id", BVType.INTEGER)]
                self.result = [[1]]
            else:
                self.command_tag = b"INSERT 0 1"
                self.columns = []
                self.result = []

        def has_results(self):
            return bool(self.result)

        def rows(self):
            return iter(self.result)

        def column_count(self):
            return len(self.columns)

    class DummySession:
        def __init__(self):
            self.in_tx = True
            self.error = False

        def execute_sql(self, sql, params=None):
            sql = sql.strip().lower()
            if sql.startswith("select"):
                return DummyQueryResult(select=True)
            else:
                return DummyQueryResult(select=False)

        def in_transaction(self):
            return self.in_tx

        def sync(self):
            self._in_error = False
            self.in_tx = False

    session = DummySession()
    ctx = BVContext(session=session, rewriter=None, params={"user": "postgres"})

    # Patch sync to use DummySession.sync
    original_sync = ctx.sync

    def patched_sync():
        session.sync()
        return original_sync()

    ctx.sync = patched_sync
    return ctx


def test_execute_select(dummy_ctx):
    result = dummy_ctx.execute_sql("SELECT 1")
    assert result.rows().__next__()[0] == 1


def test_execute_insert(dummy_ctx):
    result = dummy_ctx.execute_sql("INSERT INTO test VALUES (1)")
    assert result.command_tag == b"INSERT 0 1"


def test_portal_and_statement_handling(dummy_ctx):
    dummy_ctx.add_statement("stmt1", "SELECT 1", [])
    dummy_ctx.add_portal("portal1", "stmt1", [], [])
    result = dummy_ctx.describe_portal("portal1")
    assert result.column_count() == 1


def test_error_transaction_status(dummy_ctx):
    dummy_ctx.mark_error()
    assert dummy_ctx.transaction_status() == b"E"


def test_clear_error_on_sync(dummy_ctx):
    dummy_ctx.mark_error()
    dummy_ctx.sync()
    assert dummy_ctx.transaction_status() == b"I"
