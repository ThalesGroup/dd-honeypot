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
from sqlglot import parse_one, transpile, errors as sqlglot_errors, expressions as expr

from mysql_mimic import MysqlServer, IdentityProvider, User, NativePasswordAuthPlugin
from mysql_mimic.session import Session
from mysql_mimic.errors import MysqlError, ErrorCode
from base_honeypot import BaseHoneypot, HoneypotSession
from infra.interfaces import HoneypotAction  # Make sure this is imported
from llm_utils import invoke_llm


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


def load_config(config_file: Path):
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config file {config_file}: {e}")
        return {}


class MySession(Session):
    def __init__(self, data_handler=None, action: HoneypotAction = None, *args, **kwargs):
        self.data_handler = data_handler
        self.action = action
        self.honeypot_session: Optional[HoneypotSession] = None
        self.session_id = str(uuid.uuid4())
        self.session_vars = {}  # Store session variables here

        super().__init__(*args, **kwargs)

        self.client_address = kwargs.get("address") or (args[1] if len(args) > 1 else "unknown")
        logger.info(f"New session created: {self.session_id} from client {self.client_address}")

        if self.action:
            self.honeypot_session = self.action.connect({"client": str(self.client_address)})

        self.config_file = Path(__file__).parent / ".." / "test" / "honeypots" / "mysql" / "config.json"
        self.config = load_config(self.config_file)

        self.model_id = self.config.get("model_id", "default_model_id")
        self.system_prompt = self.config.get(
            "system_prompt",
            "You are a MySQL server emulator. Only output valid MySQL query results formatted in JSON."
        )

        self.data_file = Path(__file__).parent / ".." / "test" / "honeypots" / "mysql" / "data.jsonl"
        self.data_file.parent.mkdir(parents=True, exist_ok=True)

        self.query_response_cache = self.load_existing_data()

    async def command_handler(self, sql: str, session_id: str):
        try:
            parsed = sqlglot.parse_one(sql, read='mysql')
        except Exception:
            raise ValueError("Invalid SQL syntax")

        # Handle SET statements
        if parsed.key.upper() == "SET":
            # (your SET logic here)
            return [("OK",)], ["result"]

        # Handle SHOW statements
        if parsed.key.upper() == "SHOW":
            # (your SHOW logic here)
            return  # ...

        # Normalize query
        try:
            normalized = sqlglot.transpile(sql, read='mysql', pretty=True)[0]
        except Exception:
            normalized = " ".join(sql.strip().rstrip(";").upper().split())

        # Check cache
        if normalized in self.query_response_cache:
            cached = self.query_response_cache[normalized]
            return cached["rows"], cached["columns"]

        # Try action query sync call wrapped in executor (if needed)
        if self.action and self.honeypot_session:
            response_str = await asyncio.get_event_loop().run_in_executor(
                None, partial(self.action.query, query=sql, session=self.honeypot_session)
            )
            response = json.loads(response_str)
            self.query_response_cache[normalized] = response
            self.save_response_to_data_file(normalized, response)
            return response["rows"], response["columns"]


    def load_existing_data(self):
        if not self.data_file.exists():
            return {}
        query_to_response = {}
        with open(self.data_file, "r") as f:
            for line in f:
                try:
                    record = json.loads(line.strip())
                    query = record.get("query")
                    response = record.get("response")
                    if query and response:
                        query_to_response[query.strip()] = response
                except Exception as e:
                    logger.warning(f"Failed to parse line in {self.data_file}: {e}")
        return query_to_response

    def save_response_to_data_file(self, query: str, response: dict):
        record = {
            "query": query.strip(),
            "response": response
        }
        with open(self.data_file, "a") as f:
            f.write(json.dumps(record) + "\n")
        self.query_response_cache[query.strip()] = response

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
        logger.info(f"Handling query: {sql}")
        sql_stripped = sql.strip().rstrip(";")

        # Check cache first
        try:
            normalized = transpile(sql_stripped, read='mysql', pretty=True)[0]
        except Exception:
            normalized = " ".join(sql_stripped.upper().split())

        if normalized in self.query_response_cache:
            cached = self.query_response_cache[normalized]
            return cached["rows"], cached["columns"]

        # Handle action-based queries
        if self.action and self.honeypot_session:
            try:
                response_str = self.action.query(query=sql, session=self.honeypot_session)
                response = json.loads(response_str)
                self.query_response_cache[normalized] = response
                self.save_response_to_data_file(normalized, response)
                return response["rows"], response["columns"]
            except Exception as e:
                logger.error(f"Action query failed: {e}")

        # Fallback to data handler
        if self.data_handler:
            try:
                response = await self.data_handler.get_data(sql)
                self.query_response_cache[normalized] = response
                self.save_response_to_data_file(normalized, response)
                return response["rows"], response["columns"]
            except Exception as e:
                logger.error(f"Data handler failed: {e}")

        # Final fallback
        return [], ["No data available"]
        # Rest of your existing handle_query logic...
    async def get_or_generate_response(self, query: str) -> str:
        query = query.strip()

        if query in self.query_response_cache:
            logger.info(f"Query found in cache: {query}")
            return json.dumps(self.query_response_cache[query])

        try:
            result = await self.command_handler(query)
            self.save_response_to_data_file(query, result)
            return json.dumps(result)
        except Exception as e:
            logger.error(f"Command handler failed for query '{query}': {e}")
            fallback_response = {"columns": [], "rows": []}
            self.save_response_to_data_file(query, fallback_response)
            return json.dumps(fallback_response)


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
    def __init__(self, port, action=None, command_handler=None, identity_provider=None, **kwargs):
        super().__init__(port)

        #  Fallback to internal handler if none provided
        self.command_handler = command_handler or self._handle_sql_command
        self.identity_provider = identity_provider or AllowAllIdentityProvider()

        # Pass the now-valid command_handler into the session factory
        session_factory = partial(MySession, data_handler=self.command_handler, action=action)

        self.server = MysqlServer(
            port=self.port,
            session_factory=session_factory,
            identity_provider=self.identity_provider,
        )

        self.thread = None
        self.loop = None

    # Inside MySqlMimicHoneypot
    async def _handle_sql_command(self, sql: str, session_id: str):
        # This is a placeholder, update logic as needed
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
            pending = [t for t in asyncio.all_tasks(loop=self.loop) if t is not current_task and not t.done()]
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            self.loop.stop()

        asyncio.run_coroutine_threadsafe(shutdown(), self.loop)

    async def query(self, session_id: str, sql: str, attrs=None) -> Tuple[List[Tuple], List[str]]:
        if not hasattr(self, 'sessions'):
            self.sessions = {}

        if session_id not in self.sessions:
            session = MySession(data_handler=self.command_handler, action=getattr(self, 'action', None))
            self.sessions[session_id] = session
        else:
            session = self.sessions[session_id]

        attrs = attrs or {}

        try:
            # Handle SET commands directly
            if sql.strip().upper().startswith("SET"):
                parsed = parse_one(sql, dialect="mysql")
                if isinstance(parsed, expr.Set):
                    items = parsed.expressions
                    for item in items:
                        if isinstance(item, expr.SetItem):
                            var_name = item.this.name.lower()
                            value = item.expression.this if hasattr(item.expression, 'this') else str(item.expression)
                            session.session_vars[var_name] = value
                    return [("OK",)], ["result"]

            # Handle SHOW VARIABLES
            if sql.strip().upper().startswith("SHOW VARIABLES"):
                parsed = parse_one(sql, dialect="mysql")
                if isinstance(parsed, expr.Show) and parsed.args.get("kind", "").lower() == "variables":
                    like_expr = parsed.args.get("like")
                    if like_expr:
                        var_name = str(like_expr.this).strip("'\"")
                        value = session.session_vars.get(var_name.lower())
                        if value is not None:
                            return [(var_name, value)], ["Variable_name", "Value"]
                    return [], ["Variable_name", "Value"]

            # Handle other queries through the session
            return await session.handle_query(sql, attrs)

        except sqlglot_errors.ParseError as e:
            raise MysqlError(f"You have an error in your SQL syntax; {e}", ErrorCode.PARSE_ERROR)
        except Exception as e:
            logger.error(f"Error handling query: {e}")
            raise MysqlError(str(e), ErrorCode.UNKNOWN_ERROR)
