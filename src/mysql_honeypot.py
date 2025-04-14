import asyncio
import threading
import logging
import socket
from mysql_mimic import MysqlServer, IdentityProvider, User
from src.base_honeypot import BaseHoneypot
import time
from typing import List, Tuple, Any

logger = logging.getLogger(__name__)


class StaticQueryHandler:
    """Handles SQL queries with static responses."""

    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        logger.info(f"Received query: {sql}")
        sql = sql.upper().strip()

        if sql == "SELECT 1":
            return [(1,)], ["1"]
        elif sql.startswith("SELECT"):
            return [("test", 123)], ["col1", "col2"]
        elif sql.startswith("SHOW"):
            return [], ["empty_show_result"]
        return [], ["empty_response"]


class AllowAllIdentityProvider(IdentityProvider):
    """Allows all connections with any credentials."""

    async def get_user(self, username: str) -> User | None:
        return User(
            auth_string=None,
            auth_plugin="mysql_native_password"
        )


class MySqlMimicHoneypot(BaseHoneypot):
    def __init__(self, port: int = None):
        super().__init__(port)
        self.server = None
        self.thread = None
        self.running = False
        self.loop = None
        self.server_task = None

    def start(self):
        """Start the MySQL-Mimic honeypot server."""
        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()
        self._wait_for_server_ready()
        logger.info(f"MySQL Honeypot started on port {self.port}")

    def _run_server(self):
        """Run the MySQL-Mimic server in a separate event loop."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        try:
            # Log the attempt to start the server
            logger.info(f"Attempting to start MySQL-Mimic honeypot on port {self.port}")

            self.server = MysqlServer(
                query_handler=StaticQueryHandler(),
                identity_provider=AllowAllIdentityProvider()
            )

            # Log successful server creation
            logger.info("MysqlServer created successfully")

            # Start the server using asyncio
            coro = asyncio.start_server(
                self.server.handle_client,
                host="127.0.0.1",
                port=self.port
            )
            self.server_task = self.loop.run_until_complete(coro)
            logger.info(f"Server started on port {self.port}")

            # Keep the server running
            self.loop.run_forever()
        except Exception as e:
            # Log any exceptions that occur during startup
            logger.error(f"Error starting the server: {e}")
        finally:
            if self.server_task:
                self.server_task.close()
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
        self.running = False
        if self.loop:
            self.loop.call_soon_threadsafe(self._stop_server)
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("MySQL Honeypot stopped")

    def _stop_server(self):
        """Cleanup server resources."""
        if self.server_task:
            self.server_task.close()
        self.loop.stop()