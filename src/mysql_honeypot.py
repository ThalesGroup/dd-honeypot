import asyncio
import hashlib
import threading
import socket
import time
import uuid
import json
import logging

from pathlib import Path
from functools import partial
from typing import List, Tuple, Optional
import sqlglot
from sqlglot import parse_one, transpile, errors as sqlglot_errors, exp
from mysql_mimic import MysqlServer, IdentityProvider, User, NativePasswordAuthPlugin
from mysql_mimic.session import Session
from mysql_mimic.errors import MysqlError, ErrorCode
from base_honeypot import BaseHoneypot
from infra.interfaces import HoneypotAction  # Make sure this is imported


def setup_logging():
    logging.getLogger("mysql_mimic.connection").addFilter(
        lambda record: "You have an error in your SQL syntax" not in record.getMessage()
    )


logger = logging.getLogger(__name__)


class StaticQueryHandler:
    def __init__(self, responses=None):
        self.responses = responses or {}

    async def get_data(self, query: str) -> dict:
        query = query.strip().upper()
        return self.responses.get(query, {"columns": [], "rows": []})


def _parse_llm_response(response: str) -> Tuple[List[Tuple], List[str]]:
    try:
        parsed = json.loads(response)
        rows = [tuple(row) for row in parsed.get("rows", [])]
        columns = parsed.get("columns", [])
        if not rows or not columns:
            logger.warning("LLM response contains no rows or columns.")
            return [], ["No data available"]
        return rows, columns
    except Exception as e:
        logger.error(f"Failed to parse LLM response: {e}")
        return [], ["Invalid LLM Output"]


class MySession(Session):
    def __init__(
        self,
        base_dir=Path("data"),
        data_handler=None,
        action: HoneypotAction = None,
        config: Optional[dict] = None,  # Properly typed parameter
        *args,
        **kwargs,
    ):
        self.data_handler = data_handler
        self.action = action
        self.honeypot_session = None
        self.session_id = str(uuid.uuid4())
        self.session_vars = {}
        self.config = config or {}  # Use provided config or empty dict

        super().__init__(*args, **kwargs)

        self.client_address = kwargs.get("address") or (
            args[1] if len(args) > 1 else "unknown"
        )
        logger.info(
            f"New session created: {self.session_id} from client {self.client_address}"
        )

        if self.action:
            logger.info(
                f"[{self.session_id}] Connecting honeypot session for client {self.client_address}"
            )
            self.honeypot_session = self.action.connect(
                {"client": str(self.client_address)}
            )
            logger.info(
                f"[{self.session_id}] Honeypot session connected: {self.honeypot_session}"
            )

        self.model_id = self.config.get("model_id", "default_model_id")
        self.system_prompt = self.config.get(
            "system_prompt",
            "You are a MySQL server emulator. Only output valid MySQL query results formatted in JSON.",
        )

        self.query_response_cache = {}
        # If data_handler exists and has load capability, use it
        if data_handler and hasattr(data_handler, "load_cache"):
            try:
                self.query_response_cache = data_handler.load_cache() or {}
            except Exception as e:
                logger.warning(f"Failed to load cache from data handler: {e}")
                self.query_response_cache = {}

    async def command_handler(self, sql: str, session_id: str):
        # Improved command handler to detect and simulate DROP FUNCTION IF EXISTS sys_exec

        try:
            parsed = sqlglot.parse_one(sql, read="mysql")
        except Exception:
            raise ValueError("Invalid SQL syntax")

        # Detect DROP FUNCTION IF EXISTS sys_exec
        if (
            parsed.key.upper() == "DROP"
            and parsed.args.get("kind", "").upper() == "FUNCTION"
            and parsed.args.get("exists")
        ):
            function_name = None
            if "expressions" in parsed.args and parsed.args["expressions"]:
                first_expr = parsed.args["expressions"][0]
                if hasattr(first_expr, "name"):
                    function_name = first_expr.name.lower()
                else:
                    function_name = str(first_expr).lower()

            if function_name == "sys_exec":
                # Simulate success for dropping sys_exec
                return [("OK",)], ["result"]
            else:
                # Could simulate error or no-op for other functions
                return [("OK",)], ["result"]

        # Handle SET statements
        if parsed.key.upper() == "SET":
            return await self._handle_set_command(parsed)

        # Handle SHOW statements
        if parsed.key.upper() == "SHOW":
            # Attempt to handle multiple SHOW variants
            if isinstance(parsed, exp.Show):
                kind = parsed.args.get("kind", "").upper()
                if (
                    kind == "VARIABLES"
                    or kind == "SESSION VARIABLES"
                    or kind == "GLOBAL VARIABLES"
                ):
                    return await self._handle_show_variables(parsed)

        # Normalize query
        try:
            normalized = sqlglot.transpile(sql, read="mysql", pretty=True)[0]
        except Exception:
            normalized = " ".join(sql.strip().rstrip(";").upper().split())

        # Check cache
        if normalized in self.query_response_cache:
            cached = self.query_response_cache[normalized]
            return cached[0], cached[1]

        # Try action query sync call wrapped in executor (if needed)
        if self.action and self.honeypot_session:
            response_str = await asyncio.get_event_loop().run_in_executor(
                None,
                partial(self.action.query, query=sql, session=self.honeypot_session),
            )
            response = json.loads(response_str)
            self.query_response_cache[normalized] = response
            return response["rows"], response["columns"]

        # Fallback empty result if none matched
        return [], ["No data available"]

    async def get_llm_response(self, query: str) -> Tuple[List[Tuple], List[str]]:
        try:
            response = await self.get_or_generate_response(query)
            logger.info(f"LLM response raw data: {response}")
            if not response:
                logger.error("Empty or invalid response from LLM.")
                return [], ["Invalid LLM Output"]
            try:
                parsed = json.loads(response)
                rows = [tuple(row) for row in parsed.get("rows", [])]
                columns = parsed.get("columns", [])
                if not rows or not columns:
                    logger.warning("LLM response contains no rows or columns.")
                    return [], ["No data available"]
                return rows, columns
            except Exception as e:
                logger.error(f"Failed to parse LLM response: {e}")
                return [], ["Invalid LLM Output"]
        except Exception as e:
            logger.error(f"Failed to get LLM response: {e}")
            return [], ["Error in generating response"]

    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        logger.info(f"[{self.session_id}] Received query: {sql}")

        # Log to honeypot data log
        if hasattr(self, "honeypot"):
            self.honeypot.log_data(
                self.session_id,
                {
                    "method": "query",
                    "path": "",
                    "query_string": "",
                    "headers": {},
                    "body": sql,
                },
            )

        # First try to parse special commands (SET/SHOW)
        try:
            parsed = parse_one(sql, dialect="mysql")

            # Handle SET commands
            if isinstance(parsed, exp.Set):
                return await self._handle_set_command(parsed)

            # Handle SHOW VARIABLES
            if isinstance(parsed, exp.Show) and parsed.args.get("kind") == "VARIABLES":
                # Initialize default global variables if not set
                if not hasattr(self, "global_vars"):
                    self.global_vars = {
                        "max_allowed_packet": "1073741824",  # Default value matching test
                        "version": "8.0.0",  # Common default
                    }
                return await self._handle_show_variables(parsed)

        except sqlglot_errors.ParseError:
            # Not a parseable special command, continue normal handling
            pass
        except Exception as e:
            logger.error(f"[{self.session_id}] Parsing error: {e}")

        # Normal query handling with caching
        sql_stripped = sql.strip().rstrip(";")
        try:
            normalized = transpile(sql_stripped, read="mysql", pretty=True)[0]
        except Exception:
            normalized = " ".join(sql_stripped.upper().split())

        # Try action handler
        if self.action and self.honeypot_session:
            try:
                response_str = self.action.query(
                    query=sql, session=self.honeypot_session
                )
                response = json.loads(response_str)
                self.query_response_cache[normalized] = response

                if self.data_handler and hasattr(self.data_handler, "save_response"):
                    try:
                        self.data_handler.save_response(normalized, response)
                    except Exception as e:
                        logger.error(f"Failed to save through data handler: {e}")

                return response["rows"], response["columns"]
            except Exception as e:
                logger.error(f"Action query error: {e}")

        # Fallback to data handler
        if self.data_handler:
            try:
                if callable(self.data_handler):
                    response = await self.data_handler(self.session_id, sql)
                else:
                    response = await self.data_handler.get_data(sql)

                self.query_response_cache[normalized] = response
                return response["rows"], response["columns"]
            except Exception as e:
                logger.error(f"[{self.session_id}] Data handler error: {e}")

        logger.warning(f"[{self.session_id}] No data available for query")
        return [], ["No data available"]

    async def _handle_set_command(
        self, parsed: exp.Set
    ) -> Tuple[List[Tuple], List[str]]:
        """Handle SET commands and store variables"""
        if not hasattr(self, "global_vars"):
            self.global_vars = {}
        if not hasattr(self, "session_vars"):
            self.session_vars = {}

        for item in parsed.expressions:
            if isinstance(item, exp.SetItem):
                var_name = (
                    item.this.name if hasattr(item.this, "name") else str(item.this)
                )
                # Improved: Use .sql() to get a reliable string for complex expressions
                try:
                    value = item.expression.sql()
                except Exception:
                    # fallback to string cast if .sql() fails
                    value = str(item.expression)

                if parsed.args.get("is_global"):
                    self.global_vars[var_name] = value
                else:
                    self.session_vars[var_name] = value

        return [("OK",)], ["result"]

    async def _handle_show_variables(
        self, parsed: exp.Show
    ) -> Tuple[List[Tuple], List[str]]:
        """Handle SHOW VARIABLES commands including SESSION, GLOBAL, and LIKE patterns"""

        if not hasattr(self, "global_vars"):
            self.global_vars = {
                "max_allowed_packet": "1073741824",
                "version": "8.0.0",
            }
        if not hasattr(self, "session_vars"):
            self.session_vars = {}

        like_expr = parsed.args.get("like")
        is_global = parsed.args.get("is_global")
        is_session = (
            parsed.args.get("is_session") or parsed.args.get("scope") == "SESSION"
        )
        # Some SHOW commands use "scope" or "kind" to indicate SESSION/GLOBAL

        variables = {}

        # Support SHOW GLOBAL VARIABLES, SHOW SESSION VARIABLES, and SHOW VARIABLES (default to SESSION)
        if is_global:
            variables.update({f"@@{k}": v for k, v in self.global_vars.items()})
        elif is_session:
            variables.update({f"@{k}": v for k, v in self.session_vars.items()})
        else:
            # Default SHOW VARIABLES returns session variables per MySQL behavior
            variables.update({f"@{k}": v for k, v in self.session_vars.items()})

        # Handle LIKE pattern with % wildcard
        if like_expr:
            pattern = str(like_expr.this).strip("'\"")
            import re

            # Convert SQL LIKE pattern to regex pattern
            regex_pattern = (
                "^" + re.escape(pattern).replace(r"\%", ".*").replace(r"\_", ".") + "$"
            )

            filtered_vars = [
                (k, v) for k, v in variables.items() if re.match(regex_pattern, k)
            ]
            return filtered_vars, ["Variable_name", "Value"]

        return list(variables.items()), ["Variable_name", "Value"]

    async def get_or_generate_response(self, query: str) -> str:
        query = query.strip()
        if query in self.query_response_cache:
            return json.dumps(self.query_response_cache[query])

        try:
            result = await self.command_handler(query)
            self.query_response_cache[query] = result

            # Optional: save through data handler
            if self.data_handler and hasattr(self.data_handler, "save_response"):
                try:
                    self.data_handler.save_response(query, result)
                except Exception as e:
                    logger.error(f"Failed to save response: {e}")

            return json.dumps(result)
        except Exception as e:
            logger.error(f"Command handler failed: {e}")
            return json.dumps({"columns": [], "rows": []})


class AllowAllIdentityProvider(IdentityProvider):
    def get_plugins(self):
        return [NativePasswordAuthPlugin()]

    def get_default_plugin(self):
        return NativePasswordAuthPlugin()

    async def get_user(self, username: str) -> User:
        logger.info(f"Allowing connection for user: {username}")
        password = "123"
        stage1 = hashlib.sha1(password.encode()).digest()
        stage2 = hashlib.sha1(stage1).hexdigest()
        return User(
            name=username,
            auth_string=stage2,
            auth_plugin="mysql_native_password",
        )


class MySqlMimicHoneypot(BaseHoneypot):
    def __init__(
        self, port, action=None, command_handler=None, identity_provider=None, **kwargs
    ):
        super().__init__(port)
        self.command_handler = command_handler or self._handle_sql_command
        self.identity_provider = identity_provider or AllowAllIdentityProvider()

        session_factory = partial(
            MySession, data_handler=self.command_handler, action=action
        )
        self.server = MysqlServer(
            port=self.port,
            session_factory=session_factory,
            identity_provider=self.identity_provider,
        )
        self.server.log_data = self.log_data  # for structured logging

        self.thread = None
        self.loop = None

    async def _handle_sql_command(self, sql: str, session_id: str):
        # Placeholder handler
        return [], []

    def get_session(self, session_id):
        if session_id not in self.sessions:
            self.sessions[session_id] = MySession()
        return self.sessions[session_id]

    def set_variable(self, key, value, session_id):
        session_vars = self.sessions.setdefault(session_id, {})
        session_vars[key] = value

    def get_variable(self, key, session_id):
        return self.sessions.get(session_id, {}).get(key)

    def get_session_vars(self, session_id):
        session = self.get_session(session_id)
        return session.session_vars

    def start(self):
        """Start honeypot server in background thread and wait for it to be ready."""
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        self._wait_for_server_ready()

    def run(self):
        """Run the server with a dedicated asyncio event loop."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        async def start_server():
            await self.server.start_server(host="127.0.0.1", port=self.port)
            logger.info(f"MySQL honeypot server started on port {self.port}")

        try:
            self.loop.run_until_complete(start_server())
            self.loop.run_forever()
        except Exception as e:
            logger.error(f"Error in honeypot server run: {e}")
        finally:
            self.loop.close()

    def _wait_for_server_ready(self, retries=10, delay=0.5):
        """Wait until the honeypot server is accepting connections."""
        for _ in range(retries):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    logger.info("Honeypot server is ready")
                    return
            except (ConnectionRefusedError, OSError):
                time.sleep(delay)
        raise TimeoutError("Honeypot server did not start within the timeout period")

    def stop(self):
        """Stop the honeypot server gracefully."""
        if self.thread and self.thread.is_alive():
            self._stop_server()
            self.thread.join(timeout=2)
        logger.info("MySQL honeypot server stopped")

    def _stop_server(self):
        """Run coroutine to stop the server and cancel pending tasks."""

        async def shutdown():
            if self.server:
                await self.server.stop()
            current_task = asyncio.current_task(loop=self.loop)
            pending = [
                t
                for t in asyncio.all_tasks(loop=self.loop)
                if t is not current_task and not t.done()
            ]
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            self.loop.stop()

        asyncio.run_coroutine_threadsafe(shutdown(), self.loop)

    async def query(self, session_id: str, sql: str, attrs=None) -> Tuple[list, list]:
        if not hasattr(self, "sessions"):
            self.sessions = {}
        if session_id not in self.sessions:
            self.sessions[session_id] = MySession(
                data_handler=self.command_handler, action=getattr(self, "action", None)
            )
        session = self.sessions[session_id]
        return await session.handle_query(sql, attrs or {})
