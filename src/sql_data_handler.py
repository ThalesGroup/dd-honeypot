import json
from typing import Optional

import sqlglot

from infra.interfaces import HoneypotAction


class SqlDataHandler(HoneypotAction):
    def __init__(self, *args, dialect: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._dialect = dialect  # Accept 'mysql' or 'postgres' etc.

    def query(self, query: str, session: dict, **kwargs) -> Optional[str]:
        try:
            sqlglot.parse_one(query, dialect=self._dialect)
            if (
                query.strip()
                .upper()
                .startswith(("SET", "USE", "BEGIN", "COMMIT", "ROLLBACK"))
            ):
                return "[]"
            return None
        except sqlglot.errors.ParseError as e:
            return json.dumps([{"error": f"SQL parse error: {str(e)}"}])
