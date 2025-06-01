from typing import Optional

import sqlglot

from infra.interfaces import HoneypotAction


class SqlDataHandler(HoneypotAction):
    def __init__(self, *args, dialect: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._dialect = dialect

    def query(self, query: str, session: dict, **kwargs) -> Optional[str]:
        try:
            sqlglot.parse_one(query, dialect=self._dialect)
            return None
        except sqlglot.errors.ParseError as e:
            raise Exception(f"SQL parse error: {e}") from e
