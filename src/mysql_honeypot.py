import asyncio
import logging
import threading
from typing import Dict, Optional, Union

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
from mysql_mimic.variables import Variables
from mysql_mimic.stream import ConnectionClosed

from base_honeypot import BaseHoneypot
from honeypot_utils import wait_for_port
from infra.interfaces import HoneypotAction

import mysql_mimic.connection

logger = logging.getLogger(__name__)


def patch_client_connected_cb_to_avoid_log_errors():
    orig_client_connected_cb = mysql_mimic.server.MysqlServer._client_connected_cb

    async def safe_client_connected_cb(self, reader, writer):
        try:
            await orig_client_connected_cb(self, reader, writer)
        except (ConnectionClosed, ConnectionResetError):
            logger.info("Client disconnected cleanly (suppressed stack trace)")
        except Exception as e:
            logger.error(
                f"Unhandled exception in client_connected_cb: {e}", exc_info=True
            )

    mysql_mimic.server.MysqlServer._client_connected_cb = safe_client_connected_cb


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

        async def init(self, connection: Connection) -> None:
            if self._action:
                self._honeypot_session = self._action.connect(
                    {"connection_id": connection.connection_id}
                )
            return await super().init(connection)

        async def handle_query(
            self, sql: str, attrs: Dict[str, str]
        ) -> Union[None, tuple]:
            if self._log_data:
                self._log_data(self._honeypot_session, {"query": sql})

            upper_sql = sql.strip().upper()
            if upper_sql.startswith(("SET", "USE", "BEGIN", "COMMIT", "ROLLBACK")):
                return None

            if self._action and hasattr(self._action, "respond"):
                response = self._action.respond(sql, self._honeypot_session)
                if asyncio.iscoroutine(response):
                    response = await response
                if isinstance(response, str):
                    return ["response"], [[response]]

            # fallback
            result = await super().handle_query(sql, attrs)
            if isinstance(result, str):
                raise RuntimeError(f"Unexpected string result: {result}")
            return result

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
