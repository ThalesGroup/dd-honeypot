import json
from typing import Optional

import sqlglot
from sqlglot.expressions import Identifier, Literal, Select, Expression
from infra.interfaces import HoneypotAction


class SqlDataHandler(HoneypotAction):
    def __init__(self, *args, dialect: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._dialect = dialect

    def query(self, query: str, session: dict, **kwargs) -> Optional[str]:
        try:
            expression = sqlglot.parse_one(query, dialect=self._dialect)
        except sqlglot.errors.ParseError as e:
            return json.dumps([{"error": f"SQL parse error: {str(e)}"}])

        session.setdefault("vars", {})

        # Handle: SET @var = value
        if expression and expression.key.upper() == "SET":
            for expr in expression.expressions:
                left = getattr(expr, "this", None)
                right = getattr(expr, "expression", None)
                if isinstance(left, Identifier):
                    var_name = left.name.lstrip("@")
                    value = right.this if isinstance(right, Literal) else str(right)
                    session["vars"][var_name] = value
            return "[]"

        # Handle: SELECT @var
        if isinstance(expression, Select):
            result = {}
            only_literals = True
            for proj in expression.expressions:
                # SELECT @var -> session variable
                if isinstance(proj, Identifier) and proj.name.startswith("@"):
                    var_name = proj.name.lstrip("@")
                    result[proj.name] = session["vars"].get(var_name)
                # Evaluate literal-only expressions (e.g., SELECT 1, SELECT 2 + 3)
                elif isinstance(proj, Expression):
                    try:
                        compiled = proj.sql(dialect=self._dialect)
                        if any(
                            token in compiled.upper()
                            for token in ["FROM", "ILIKE", "LIKE"]
                        ):
                            return None
                        val = proj.evaluate()
                        return json.dumps([[val]])
                    except:
                        only_literals = False

            if result:
                return json.dumps([result])
            if only_literals:
                return None

        # Accept common transactional / SET commands
        safe_commands = {
            "USE",
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "SET NAMES",
            "SET CHARACTER SET",
            "SET CHARSET",
        }
        if any(query.upper().startswith(cmd) for cmd in safe_commands):
            return "[]"

        return None
