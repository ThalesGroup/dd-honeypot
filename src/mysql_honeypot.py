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

            # Handle SET @var = value
            if query.lower().startswith("set @"):
                try:
                    var_expr = query[4:]  # Skip 'SET '
                    var_name, value = [s.strip() for s in var_expr.split("=", 1)]
                    var_name = var_name.lstrip("@")
                    try:
                        value = json.loads(value)
                    except Exception:
                        pass
                    self._session_data["vars"][var_name] = value
                    return [], []
                except Exception:
                    logger.warning(f"Bad SET @var query: {sql}")
                    raise Exception("Malformed SET query")

            # Handle SELECT @var
            if query.lower().startswith("select @"):
                try:
                    var_name = query[7:].strip().lstrip("@")
                    value = self._session_data["vars"].get(var_name)
                    return [(value,)], [f"@{var_name}"]

                except Exception:
                    logger.warning(f"Bad SELECT @var query: {sql}")
                    raise Exception("Malformed SELECT query")

            # Try default MySQL mimic first
            result = await super().handle_query(sql, attrs)
            if result and result[0]:
                return result

            # LLM fallback
            context = dict(session=self._session_data, **(self._honeypot_session or {}))
            response = self._action.query(sql, context, **attrs)

            if response == "[]":
                return [], []

            try:
                parsed = json.loads(response)
                if isinstance(parsed, list) and parsed:
                    return [tuple(row.values()) for row in parsed], list(
                        parsed[0].keys()
                    )
            except Exception as e:
                logger.warning(f"Failed to parse LLM response: {e}")
            return [], []

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
