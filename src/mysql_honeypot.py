import asyncio
import hashlib
import re
import threading
import socket
import time
import uuid
import json
import logging

from pathlib import Path
from functools import partial
from typing import List, Tuple, Optional, Dict
import sqlglot
from mysql.connector import errorcode
from sqlglot import transpile, errors as sqlglot_errors, exp, ParseError
from mysql_mimic import MysqlServer, IdentityProvider, User, NativePasswordAuthPlugin
from mysql_mimic.session import Session
from mysql_mimic.errors import MysqlError, ErrorCode
from base_honeypot import BaseHoneypot
from infra.interfaces import HoneypotAction


def setup_logging():
    logging.getLogger("mysql_mimic.connection").addFilter(
        lambda record: "You have an error in your SQL syntax" not in record.getMessage()
    )


logger = logging.getLogger(__name__)

# ==================== Infrastructure Components ====================


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


class BaseHoneypotSession(Session):
    """Infrastructure code that could work with any database"""

    def __init__(
        self,
        base_dir=Path("data"),
        data_handler=None,
        action: HoneypotAction = None,
        config: Optional[dict] = None,
        command_handler=None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.data_handler = data_handler
        self.action = action
        self.honeypot_session = None
        self.session_id = str(uuid.uuid4())
        self.config = config or {}
        self.command_handler = command_handler

        self.client_address = kwargs.get("address") or (
            args[1] if len(args) > 1 else "unknown"
        )
        self.query_response_cache = {}

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

        if data_handler and hasattr(data_handler, "load_cache"):
            try:
                self.query_response_cache = data_handler.load_cache() or {}
            except Exception as e:
                logger.warning(f"Failed to load cache from data handler: {e}")

    async def get_llm_response(self, query: str) -> Tuple[List[Tuple], List[str]]:
        """Generic LLM response handling"""
        try:
            response = await self.get_or_generate_response(query)
            logger.info(f"LLM response raw data: {response}")
            if not response:
                logger.error("Empty or invalid response from LLM.")
                return [], ["Invalid LLM Output"]
            return _parse_llm_response(response)
        except Exception as e:
            logger.error(f"Failed to get LLM response: {e}")
            return [], ["Error in generating response"]

    async def get_or_generate_response(self, query: str) -> str:
        """Generic response generation"""
        query = query.strip()
        if query in self.query_response_cache:
            return json.dumps(self.query_response_cache[query])

        try:
            result = await self.command_handler(query, session_id=self.session_id)
            self.query_response_cache[query] = result

            if self.data_handler and hasattr(self.data_handler, "save_response"):
                try:
                    self.data_handler.save_response(query, result)
                except Exception as e:
                    logger.error(f"Failed to save response: {e}")

            return json.dumps(result)
        except Exception as e:
            logger.error(f"Command handler failed: {e}")
            return json.dumps({"columns": [], "rows": []})

    @staticmethod
    def parse_sql(sql: str) -> exp.Expression:
        try:
            return sqlglot.parse_one(sql, dialect="mysql")
        except sqlglot_errors.ParseError as e:
            logger.error(f"SQL parse error: {e}")
            raise MysqlError(
                f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax near '{sql[:30]}...'",
                code=errorcode.ER_PARSE_ERROR,
            )


# ==================== MySQL-Specific Implementation ====================


class MySession(BaseHoneypotSession):
    """MySQL-specific session implementation"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.global_vars = {}
        self.session_vars = {}
        self.query_response_cache = {}
        self.model_id = self.config.get("model_id", "default_model_id")
        self.system_prompt = self.config.get(
            "system_prompt",
            "You are a MySQL server emulator. Only output valid MySQL query results formatted in JSON.",
        )

    async def command_handler(
        self, sql: str, session_id: str
    ) -> Tuple[List[Tuple], List[str]]:
        """MySQL-specific command handling"""
        try:
            parsed = sqlglot.parse_one(sql, dialect="mysql")
        except Exception:
            raise ValueError("Invalid SQL syntax")

        # Handle DROP FUNCTION ... IF EXISTS sys_exec;
        if (
            parsed.key.upper() == "DROP"
            and parsed.args.get("kind", "").upper() == "FUNCTION"
            and parsed.args.get("exists") is True
        ):
            function_name = None
            expressions = parsed.args.get("expressions", [])
            if expressions:
                first_expr = expressions[0]
                if hasattr(first_expr, "name"):
                    function_name = first_expr.name.lower()
                else:
                    function_name = str(first_expr).lower()
            # For now, return OK for sys_exec or any other function
            return [("OK",)], ["result"]

        # Handle SET commands
        if isinstance(parsed, exp.Set):
            return await self._handle_set_command(parsed)

        # Handle SHOW VARIABLES commands
        if parsed.key.upper() == "SHOW" and isinstance(parsed, exp.Show):
            kind = parsed.args.get("kind", "").upper()
            if kind in ("VARIABLES", "SESSION VARIABLES", "GLOBAL VARIABLES"):
                return await self._handle_show_variables(parsed)

        # Normalize and cache query responses
        try:
            normalized = transpile(sql, read="mysql", pretty=True)[0]
        except sqlglot_errors.ParseError:
            normalized = " ".join(sql.strip().rstrip(";").upper().split())

        if normalized in self.query_response_cache:
            cached = self.query_response_cache[normalized]
            return cached[0], cached[1]

        if self.action and self.honeypot_session:
            func = partial(self.action.query, query=sql, session=self.honeypot_session)
            response_str = await asyncio.get_event_loop().run_in_executor(None, func)  # type: ignore[arg-type]
            response = json.loads(response_str)
            self.query_response_cache[normalized] = response
            return response["rows"], response["columns"]

        return [], ["No data available"]

    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        """MySQL-specific query handling"""
        logger.info(f"[{self.session_id}] Received query: {sql}")

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

        try:
            parsed = sqlglot.parse_one(sql, dialect="mysql")

            if isinstance(parsed, exp.Set):
                return await self._handle_set_command(parsed)

            if isinstance(parsed, exp.Show):
                kind = parsed.args.get("kind", "").upper()
                if kind in ("VARIABLES", "SESSION VARIABLES", "GLOBAL VARIABLES"):
                    # Initialize global vars if empty
                    if not self.global_vars:
                        self.global_vars = {
                            "max_allowed_packet": "1073741824",
                            "version": "8.0.0",
                        }
                    return await self._handle_show_variables(parsed)

            # Add more SQL command types if needed
            if isinstance(parsed, (exp.Select, exp.Insert, exp.Update, exp.Delete)):
                # Let the fallback handle these
                pass

        except sqlglot_errors.ParseError as e:
            logger.error(f"[{self.session_id}] SQL parse error: {e}")
            raise MysqlError(
                f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{sql[:30]}...'",
                code=errorcode.ER_PARSE_ERROR,
            )
        except Exception as e:
            logger.error(f"[{self.session_id}] Error parsing SQL: {e}")
            raise MysqlError(
                "Internal server error while parsing SQL",
                code=errorcode.ER_INTERNAL_ERROR,
            )

        sql_stripped = sql.strip().rstrip(";")
        try:
            normalized = transpile(sql_stripped, read="mysql", pretty=True)[0]
        except (sqlglot_errors.ParseError, IndexError):
            normalized = " ".join(sql_stripped.upper().split())

        if self.action and self.honeypot_session:
            try:
                response_str = self.action.query(
                    query=sql, session=self.honeypot_session
                )
                response = json.loads(response_str)
                self.query_response_cache[normalized] = response
                return response["rows"], response["columns"]
            except Exception as e:
                logger.error(f"[{self.session_id}] Action query error: {e}")

        if self.data_handler:
            try:
                if callable(self.data_handler):
                    response = await self.data_handler(self.session_id, sql)
                else:
                    response = await self.data_handler.get_data(sql)
                return response["rows"], response["columns"]
            except Exception as e:
                logger.error(f"[{self.session_id}] Data handler error: {e}")

        return [], ["No data available"]

    async def _handle_set_command(
        self, parsed: exp.Set
    ) -> Tuple[List[Tuple], List[str]]:
        """MySQL-specific SET command handling"""
        for item in parsed.expressions:
            if isinstance(item, exp.SetItem):
                var_name = (
                    item.this.name if hasattr(item.this, "name") else str(item.this)
                )
                try:
                    value = item.expression.sql()
                except (AttributeError, TypeError, sqlglot_errors.ParseError):
                    value = str(item.expression)

                if parsed.args.get("is_global"):
                    self.global_vars[var_name] = value
                else:
                    self.session_vars[var_name] = value

        return [("OK",)], ["result"]

    async def _handle_show_variables(
        self, parsed: exp.Show
    ) -> Tuple[List[Tuple], List[str]]:
        """MySQL-specific SHOW VARIABLES handling"""
        like_expr = parsed.args.get("like")
        is_global = parsed.args.get("is_global")
        is_session = (
            parsed.args.get("is_session") or parsed.args.get("scope") == "SESSION"
        )

        variables = {}
        if is_global:
            variables.update({f"@@{k}": v for k, v in self.global_vars.items()})
        elif is_session:
            variables.update({f"@{k}": v for k, v in self.session_vars.items()})
        else:
            variables.update({f"@{k}": v for k, v in self.session_vars.items()})

        if like_expr:
            pattern = str(like_expr.this).strip("'\"")
            regex_pattern = (
                "^" + re.escape(pattern).replace(r"\%", ".*").replace(r"\_", ".") + "$"
            )
            filtered_vars = [
                (k, v) for k, v in variables.items() if re.match(regex_pattern, k)
            ]
            return filtered_vars, ["Variable_name", "Value"]

        return list(variables.items()), ["Variable_name", "Value"]


class AllowAllIdentityProvider(IdentityProvider):
    """MySQL-specific authentication provider"""

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
    """MySQL-specific honeypot implementation"""

    sessions: Dict[str, MySession]

    def __init__(self, port, action=None, command_handler=None, identity_provider=None):
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
        self.server.log_data = self.log_data

        self.thread = None
        self.loop = None

    @staticmethod
    async def _handle_sql_command():
        return [], []

    def get_session(self, session_id):
        if session_id not in self.sessions:
            self.sessions[session_id] = MySession()
        return self.sessions[session_id]

    def set_variable(self, key, value, session_id):
        session = self.sessions.setdefault(session_id, MySession())
        session.variables[key] = value

    def get_variable(self, key, session_id):
        return self.sessions.get(session_id, {}).get(key)

    def get_session_vars(self, session_id):
        session = self.get_session(session_id)
        return session.session_vars

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        self._wait_for_server_ready()

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        async def start_server():
            await self.server.start_server(host="0.0.0.0", port=self.port)
            logger.info(f"MySQL honeypot server started on port {self.port}")

        try:
            self.loop.run_until_complete(start_server())
            self.loop.run_forever()
        except Exception as e:
            logger.error(f"Error in honeypot server run: {e}")
        finally:
            self.loop.close()

    def _wait_for_server_ready(self, retries=4, delay=0.5):
        for _ in range(retries):
            try:
                with socket.create_connection(("0.0.0.0", self.port), timeout=1):
                    logger.info("Honeypot server is ready")
                    return
            except (ConnectionRefusedError, OSError):
                time.sleep(delay)
        raise TimeoutError("Honeypot server did not start within the timeout period")

    def stop(self):
        if self.thread and self.thread.is_alive():
            self._stop_server()
            self.thread.join(timeout=2)
        logger.info("MySQL honeypot server stopped")

    def _stop_server(self):
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
            self.sessions = {}  # type: ignore[assignment]
        if session_id not in self.sessions:
            self.sessions[session_id] = MySession(
                data_handler=self.command_handler, action=getattr(self, "action", None)
            )
        session = self.sessions[session_id]
        return await session.handle_query(sql, attrs or {})
