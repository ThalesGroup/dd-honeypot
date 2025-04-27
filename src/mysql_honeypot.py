import asyncio
import hashlib
import json
import threading
import logging
import socket
import time
from typing import List, Tuple
import boto3

import pymysql
from mysql_mimic import MysqlServer, IdentityProvider, User, NativePasswordAuthPlugin
from mysql_mimic.session import Session
from src.base_honeypot import BaseHoneypot
from mysql_mimic.server import MysqlServer
from src.llm_utils import get_or_generate_response

# Suppress noisy SQL syntax error logs
logging.getLogger("mysql_mimic.connection").addFilter(
    lambda record: "You have an error in your SQL syntax" not in record.getMessage()
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize the Bedrock client
bedrock_client = boto3.client('bedrock-runtime')


class StaticQueryHandler:
    def __init__(self, responses=None):
        self.responses = responses or {}

    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        logger.info(f"Received query: {sql}")
        sql = sql.upper().strip()
        return self.responses.get(sql, ([], ["empty_response"]))


class MySession(Session):
    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        logger.info(f"Handling query: {sql}")
        sql = sql.upper().strip()

        # Simulate access denial for invalid users
        if attrs.get("user") == "attacker":
            raise pymysql.MySQLError("Access denied for user 'attacker'@'localhost' (using password: YES)")

        # Handle specific queries
        if sql == "SELECT 1":
            return [("1",)], ["1"]
        elif sql == "SELECT * FROM USERS":
            return [("person1",), ("person2",)], ["username"]
        elif sql == "SHOW DATABASES":
            return [("testdb",)], ["Database"]

        # Handle SET NAMES query (simulating expected behavior)
        if sql.startswith("SET NAMES"):
            charset = sql.split()[2]  # Extract the charset from the query (e.g., 'latin1')
            logger.info(f"Simulating 'SET NAMES {charset}' query")
            return [], []

        # Fallback to LLM response if no predefined query is matched
        try:
            rows, columns = await self.get_llm_response(sql)
            return rows, columns
        except Exception as e:
            logger.error(f"Failed to get LLM response: {e}")
            raise pymysql.MySQLError(f"You have an error in your SQL syntax near '{sql}'")

    # In the method that processes the LLM response (inside `MySession` class):
    @staticmethod
    async def get_llm_response(sql: str) -> Tuple[List[Tuple], List[str]]:
        try:
            # Get the raw response from the LLM
            response = await get_or_generate_response(sql)  # Ensure this is awaited if the function is async

            # Log the raw LLM response
            logger.info(f"LLM response raw data: {response}")

            if not response:  # Check if the response is empty or None
                logger.error("Empty or invalid response from LLM.")
                return [], ["Invalid LLM Output"]

            try:
                # Parse the LLM response
                parsed = json.loads(response)
                rows = [tuple(row) for row in parsed.get("rows", [])]
                columns = parsed.get("columns", [])

                # If no rows or columns returned, handle gracefully
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
    def __init__(self, port: int = None, identity_provider=None):
        super().__init__(port)
        self.identity_provider = identity_provider or AllowAllIdentityProvider()
        self.server = MysqlServer(
            port=self.port,
            session_factory=MySession,
            identity_provider=self.identity_provider,
            plugins=[NativePasswordAuthPlugin()]  # <-- This is key
        )
        self.thread = None
        self.loop = None
        logger.info(f"Using identity provider: {self.identity_provider.__class__.__name__}")

    def start(self):
        """Start honeypot in a background thread and wait for readiness."""
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        self._wait_for_server_ready()

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        try:
            self.server = MysqlServer(
                port=self.port,
                session_factory=MySession,
                identity_provider=self.identity_provider,
            )

            async def start_server():
                await self.server.start_server(host="127.0.0.1", port=self.port)
                logger.info(f"Server started on port {self.port}")

            self.loop.run_until_complete(start_server())
            self.loop.run_forever()

        except Exception as e:
            logger.error(f"Error starting server: {e}")
        finally:
            self.loop.close()

    def _wait_for_server_ready(self, retries=10, delay=0.5):
        for _ in range(retries):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    logger.info("Server is ready")
                    return
            except (ConnectionRefusedError, OSError):
                time.sleep(delay)
        raise TimeoutError("Honeypot did not start within timeout.")

    def stop(self):
        if self.loop:
            self.loop.call_soon_threadsafe(self._stop_server)
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("MySQL Honeypot stopped")

    def _stop_server(self):
        async def shutdown():
            if self.server:
                await self.server.stop()
            for task in asyncio.all_tasks(loop=self.loop):
                if not task.done():
                    task.cancel()
            self.loop.stop()

        asyncio.run_coroutine_threadsafe(shutdown(), self.loop)
