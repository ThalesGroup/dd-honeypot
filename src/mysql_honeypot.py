import asyncio
import hashlib
import threading
import socket
import time
from functools import partial
from typing import List, Tuple
import os
from mysql_mimic import MysqlServer, IdentityProvider, User, NativePasswordAuthPlugin
from mysql_mimic.session import Session
from src.base_honeypot import BaseHoneypot
from mysql_mimic.errors import MysqlError, ErrorCode
import json
import logging
from pathlib import Path
from src.llm_utils import invoke_llm


def setup_logging():
    logging.getLogger("mysql_mimic.connection").addFilter(
        lambda record: "You have an error in your SQL syntax" not in record.getMessage()
    )


# Configure logging
logger = logging.getLogger(__name__)


# Class to handle static queries and responses.
class StaticQueryHandler:
    def __init__(self, responses=None):
        self.responses = responses or {}

    async def get_data(self, query: str) -> dict:
        """Method to return mock data based on the query."""
        query = query.strip().upper()
        return self.responses.get(query, {"columns": [], "rows": []})


# Parsing function for LLM responses.
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


# Loads configuration from a JSON file
def load_config(config_file: Path):
    """Loads configuration from the given JSON file."""
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config file {config_file}: {e}")
        return {}


class MySession(Session):
    def __init__(self, data_handler=None, *args, **kwargs):
        self.data_handler = data_handler  # Accept data_handler as part of session init
        super().__init__(*args, **kwargs)

        # Load LLM Config from MySQL honeypot config file
        self.config_file = Path(__file__).parent / ".." / "test" / "honeypots" / "mysql" / "config.json"
        self.config = load_config(self.config_file)

        # Set model_id and system_prompt from config file
        self.model_id = self.config.get("model_id", "default_model_id")
        self.system_prompt = self.config.get("system_prompt",
                                             "You are a MySQL server emulator. Only output valid MySQL query results formatted in JSON.")

        # Set data.jsonl path
        self.data_file = Path(__file__).parent / ".." / "test" / "honeypots" / "mysql" / "data.jsonl"
        self.data_file.parent.mkdir(parents=True, exist_ok=True)

        # Load cache
        self.query_response_cache = self.load_existing_data()

    async def command_handler(self, sql: str):
        # Normalize SQL for matching
        normalized = " ".join(sql.strip().rstrip(";").upper().split())

        # First check if it's in the cache
        if normalized in self.query_response_cache:
            return self.query_response_cache[normalized]["rows"], self.query_response_cache[normalized]["columns"]

        # If no cache and no data_handler, raise error
        if not self.data_handler:
            raise MysqlError("No valid handler for query", ErrorCode.UNKNOWN_ERROR)

        # Use DataHandler to get response
        response = await self.data_handler.get_data(query=sql)

        # Cache the new response
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
        """Returns the LLM-generated response for the SQL query."""
        try:
            # Fetch the raw response from the LLM
            response = await self.get_or_generate_response(query)
            logger.info(f"LLM response raw data: {response}")
            if not response:  # Check if the response is empty or None
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

    # Handle incoming queries
    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        logger.info(f"Handling query: {sql}")
        sql = sql.strip().upper()

        # Example of hardcoded responses
        if attrs.get("user") == "attacker":
            raise MysqlError("You have an error in your SQL syntax", ErrorCode.PARSE_ERROR)
        elif sql == "SELECT 1":
            return [(1,)], ["1"]
        elif sql == "SHOW DATABASES":
            return [("testdb",)], ["Database"]
        elif sql == "INVALID QUERY":
            raise MysqlError("You have an error in your SQL syntax", ErrorCode.PARSE_ERROR)

        # Delegate to the command handler for other queries
        response = await self.command_handler(sql)
        return response

    async def get_or_generate_response(self, query: str) -> str:
        query = query.strip()

        # Check if the query response is cached
        if query in self.query_response_cache:
            logger.info(f"Query found in cache: {query}")
            return json.dumps(self.query_response_cache[query])

        try:
            # If data handler exists, use it to get the response
            if self.command_handler:
                result = await self.command_handler(query)
                self.save_response_to_data_file(query, result)
                return json.dumps(result)

            # If no handler, fallback to LLM invocation
            response_text = invoke_llm(
                system_prompt=self.system_prompt,
                user_prompt=query,
                model_id=self.model_id
            )
            parsed_response = json.loads(response_text)
            self.save_response_to_data_file(query, parsed_response)
            return json.dumps(parsed_response)
        except Exception as e:
            logger.error(f"LLM generation failed for query '{query}': {e}")
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
    def __init__(self, port: int = None, command_handler=None, identity_provider=None, **kwargs):
        super().__init__(port)
        self.command_handler = command_handler  # Shared command handler for queries
        self.identity_provider = identity_provider or AllowAllIdentityProvider()

        # Session factory is now partial with command_handler
        session_factory = partial(MySession, data_handler=self.command_handler)

        # Create the MySQL server with the session factory and identity provider
        self.server = MysqlServer(
            port=self.port,
            session_factory=session_factory,
            identity_provider=self.identity_provider,
        )

        self.thread = None
        self.loop = None

    def start(self):
        """Start honeypot in a background thread and wait for readiness."""
        setup_logging()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        self._wait_for_server_ready()

    def run(self):
        from mysql_mimic.stream import ConnectionClosed  # avoid global import
        import socket  # <-- needed to catch socket errors
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        original_cb = self.server._client_connected_cb

        async def safe_cb(reader, writer):
            try:
                await original_cb(reader, writer)
            except (ConnectionClosed, ConnectionResetError, OSError, socket.error):
                # These are expected when clients disconnect abruptly
                logger.debug("Client disconnected (handled gracefully)")
            except Exception:
                logger.exception("Unhandled exception in client_connected_cb")
        self.server._client_connected_cb = safe_cb
        try:
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
            current_task = asyncio.current_task(loop=self.loop)
            pending = [t for t in asyncio.all_tasks(loop=self.loop) if t is not current_task and not t.done()]
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            self.loop.stop()
        asyncio.run_coroutine_threadsafe(shutdown(), self.loop)