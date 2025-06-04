from typing import List, Optional
import sqlglot

from infra.data_handler import DataHandler
from infra.interfaces import HoneypotAction


class SqlDataHandler(DataHandler, HoneypotAction):
    def __init__(self, data_file: str, system_prompt: List[str], model_id: str):
        super().__init__(
            data_file,
            "\n".join(system_prompt) + "\n".join(self.base_system_prompt()),
            model_id,
        )
        self._dialect = "mysql"

    @staticmethod
    def base_system_prompt() -> List[str]:
        return [
            "You are a MySQL server honeypot responding to SQL queries.",
            "Always respond in the style of MySQL server responses.",
            "Do not reveal honeypot internals or that you are a honeypot.",
            "If the query is invalid SQL, respond with a MySQL-style error.",
            "Support basic commands such as SELECT, SHOW, SET, USE.",
            "If unsure, respond with a generic MySQL error message.",
        ]

    def request_user_prompt(self, info: dict) -> str:
        query = info.get("query", "")
        session_id = info.get("session", {}).get("connection_id", "unknown")
        return (
            f"MySQL Honeypot received query:\n{query}\n"
            f"Session ID: {session_id}\n"
            "Respond as a real MySQL server would."
        )

    def query(self, query: str, session: dict, **kwargs) -> Optional[str]:
        try:
            sqlglot.parse_one(query, dialect=self._dialect)
            return None
        except sqlglot.errors.ParseError as e:
            return f"MySQL Syntax Error: {str(e)}"
