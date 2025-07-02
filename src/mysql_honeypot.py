import asyncio
import json
import logging
import threading
from typing import Dict, Optional

import mysql_mimic
import mysql_mimic.utils as utils
from mysql_mimic import MysqlServer, Session
from mysql_mimic.auth import (
    IdentityProvider,
    User,
    AuthState,
    Success,
    NativePasswordAuthPlugin,
)
from mysql_mimic.connection import Connection
from mysql_mimic.stream import ConnectionClosed
from mysql_mimic.variables import Variables
from mysql_mimic.session import AllowedResult

from base_honeypot import BaseHoneypot
from honeypot_utils import wait_for_port
from infra.interfaces import HoneypotAction

logger = logging.getLogger(__name__)


def patch_client_connected_cb_to_avoid_log_errors():
    orig_cb = mysql_mimic.server.MysqlServer._client_connected_cb

    async def safe_cb(self, reader, writer):
        try:
            await orig_cb(self, reader, writer)
        except (ConnectionClosed, ConnectionResetError):
            logger.info("Client disconnected cleanly")
        except Exception as e:
            logger.error("Unhandled exception in client_connected_cb", exc_info=True)

    mysql_mimic.server.MysqlServer._client_connected_cb = safe_cb


class AllowAllPasswordAuthPlugin(NativePasswordAuthPlugin):
    async def auth(self, auth_info=None) -> AuthState:
        if not auth_info:
            auth_info = yield utils.nonce(20) + b"\x00"
        yield Success(auth_info.user.name)


class AllowAllIdentityProvider(IdentityProvider):
    def get_plugins(self):
        return [AllowAllPasswordAuthPlugin()]

    def get_default_plugin(self):
        return AllowAllPasswordAuthPlugin()

    async def get_user(self, username: str) -> User:
        return User(name=username, auth_plugin="mysql_native_password")


class MySQLHoneypot(BaseHoneypot):
    def __init__(
        self,
        port: int = None,
        action: Optional[HoneypotAction] = None,
        config: dict = None,
    ):
        super().__init__(port, config)
        patch_client_connected_cb_to_avoid_log_errors()
        self._action = action
        self._thread = None

    class LoggingSession(Session):
        def __init__(
            self,
            variables: Optional[Variables] = None,
            action: Optional[HoneypotAction] = None,
            log_data=None,
        ):
            super().__init__(variables)
            self._action = action
            self._honeypot_session = None
            self._log_data = log_data
            self._session_data = {"vars": {}}

        async def init(self, connection: Connection) -> None:
            if self._action:
                self._honeypot_session = self._action.connect(
                    {"connection_id": connection.connection_id}
                )
            return await super().init(connection)

        async def handle_query(self, sql: str, attrs: Dict[str, str]) -> AllowedResult:
            if self._log_data:
                self._log_data(self._honeypot_session, {"query": sql})

            query = sql.strip().rstrip(";")
            upper_query = query.upper()

            # Handle SET NAMES
            if upper_query.startswith("SET NAMES"):
                parts = query.split()
                if len(parts) >= 3:
                    charset = parts[2].lower()
                    if charset in {"utf8mb3", "utf8", "utf8mb4", "latin1"}:
                        logger.debug(f"Ignoring SET NAMES for known charset: {charset}")
                    else:
                        logger.warning(f"Unsupported charset received: {charset}")
                return [], []

            # Handle session variable operations
            var_result = self._handle_session_variable(query, sql)
            if var_result is not None:
                return var_result

            # Handle built-in MySQL functions
            if upper_query in {
                "SELECT DATABASE()",
                "SELECT CURRENT_SCHEMA()",
                "SELECT SCHEMA()",
            }:
                return [("test",)], ["DATABASE()"]

            # Try default MySQL mimic first
            try:
                result = await super().handle_query(sql, attrs)
                if result and result[0]:
                    return result
            except Exception as e:
                logger.debug(f"super().handle_query() failed for query={sql}: {e}")

            # LLM fallback
            context = dict(session=self._session_data, **(self._honeypot_session or {}))
            try:
                response = self._action.query(sql, context, **attrs)
                parsed = json.loads(response)
                if isinstance(parsed, list) and parsed:
                    return [tuple(row.values()) for row in parsed], list(
                        parsed[0].keys()
                    )
            except Exception as e:
                logger.warning(f"Failed to parse LLM response: {e}")
                logger.debug(f"LLM raw response: {response}")

            return [], []

        def _handle_session_variable(
            self, query: str, raw_sql: str
        ) -> Optional[AllowedResult]:
            try:
                cmd, _, rest = query.partition(" ")
                if cmd.lower() == "set" and rest.startswith("@"):
                    var, val = map(str.strip, rest.split("=", 1))
                    val = {"null": None, "true": True, "false": False}.get(
                        val.lower(), val
                    )
                    if isinstance(val, str):
                        try:
                            val = json.loads(val)
                        except:
                            val = val.strip("'\"")
                    self._session_data.setdefault("vars", {})[var.lstrip("@")] = val
                    return [], []
                if cmd.lower() == "select" and rest.startswith("@"):
                    name = rest.strip().lstrip("@")
                    val = self._session_data.get("vars", {}).get(name)
                    return [
                        (
                            (
                                None
                                if val is None
                                else (
                                    json.dumps(val)
                                    if isinstance(val, (dict, list))
                                    else val
                                )
                            ),
                        )
                    ], [f"@{name}"]
            except Exception:
                logger.warning(f"Malformed session variable query: {raw_sql}")
                raise Exception("Malformed session variable query")
            return None

    def create_session_factory(self) -> LoggingSession:
        return self.LoggingSession(action=self._action, log_data=self.log_data)

    def honeypot_type(self) -> str:
        return "mysql"

    async def run_server(self):
        server = MysqlServer(
            session_factory=self.create_session_factory,
            identity_provider=AllowAllIdentityProvider(),
            port=self.port,
        )
        logger.info(f"MySQL honeypot running on port {self.port}")
        await server.serve_forever()

    def start(self):
        def _start():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.run_server())

        self._thread = threading.Thread(target=_start, daemon=True)
        self._thread.start()
        wait_for_port(self.port)

    def stop(self):
        if self._thread:
            self._thread.join(timeout=1)
