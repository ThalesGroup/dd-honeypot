import asyncio
import threading
import logging
import socket
from mysql_mimic import MysqlServer, IdentityProvider, User
from src.base_honeypot import BaseHoneypot
import time
from typing import List, Tuple, Any
from mysql_mimic.session import Session

logger = logging.getLogger(__name__)

class StaticQueryHandler:
    def __init__(self, responses=None):
        self.responses = responses or {}

    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        logger.info(f"Received query: {sql}")
        sql = sql.upper().strip()
        return self.responses.get(sql, ([], ["empty_response"]))

class MySession(Session):
    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        sql = sql.upper().strip()
        if sql == "SELECT 1":
            return [("1",)], ["1"]
        elif sql == "SELECT * FROM USERS":
            return [("alice",), ("bob",)], ["username"]
        elif sql == "SHOW DATABASES":
            return [("testdb",)], ["Database"]
        return [], ["empty_response"]
class AllowAllIdentityProvider(IdentityProvider):
    #Allows all connections with any credentials.

    async def get_user(self, username: str) -> User:
        logger.info(f"Allowing connection for user: {username}")
        return User(
            name=username,
            auth_string=None,  # No authentication required
            auth_plugin="mysql_native_password"
        )

    async def authenticate(self, user: User, password: str) -> bool:
        # Log the authentication attempt for debugging
        logger.info(f"Authenticating user {user.name} with password {password}")
        # Override authentication to always succeed
        return True  # Always allow the connection, ignoring credentials

class MySqlMimicHoneypot(BaseHoneypot):
    def __init__(self, port: int = None, identity_provider=None):
        super().__init__(port)
        self.identity_provider = identity_provider or AllowAllIdentityProvider()
        self.server = None
        self.thread = None
        self.running = False
        self.loop = None
        self.server_task = None

    def start(self):
        """Start the MySQL-Mimic honeypot server."""
        self.running = True

        # Start the server in a separate thread
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()

        # Wait for the server to be ready
        self._wait_for_server_ready()

        logger.info(f"MySQL Honeypot started on port {self.port}")

    def _run_server(self):
        """Run the MySQL-Mimic server in a separate event loop."""
        logger.debug("Starting _run_server")

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        try:
            logger.info(f"Attempting to start MySQL-Mimic honeypot on port {self.port}")

            self.server = MysqlServer(
                port=self.port,
                session_factory=MySession,
                identity_provider=self.identity_provider,
            )

            async def start_server():
                await self.server.start_server(host="127.0.0.1", port=self.port)
                logger.info(f"Server started on port {self.port}")

            # Run startup and then loop forever
            self.loop.run_until_complete(start_server())
            self.loop.run_forever()

        except Exception as e:
            logger.error(f"Error starting the server: {e}")
        finally:
            self.loop.close()

    def _wait_for_server_ready(self, retries=10, delay=1):
        """Wait until server is accepting connections."""
        for i in range(retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex(('127.0.0.1', self.port)) == 0:
                        logger.info(f"Server ready on port {self.port}")
                        return
            except socket.error:
                pass
            time.sleep(delay)
        raise RuntimeError(f"Server failed to start on port {self.port}")

    def stop(self):
        """Stop the honeypot server."""
        logger.debug("Beginning stop procedure")

        self.running = False
        if self.loop:
            try:
                self.loop.call_soon_threadsafe(self._stop_server)
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("MySQL Honeypot stopped")

    def _stop_server(self):
        """Cleanup server resources."""

        async def shutdown():
            if self.server:
                await self.server.stop()

            tasks = [t for t in asyncio.all_tasks(loop=self.loop) if not t.done()]
            for task in tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            self.loop.stop()

        # Run shutdown in thread-safe way
        asyncio.run_coroutine_threadsafe(shutdown(), self.loop)
