import asyncio
import hashlib
import json
import threading
import logging
import socket
import time
from pathlib import Path
from typing import List, Tuple
import os
import boto3
import pymysql
from mysql_mimic import MysqlServer, IdentityProvider, User, NativePasswordAuthPlugin
from mysql_mimic.session import Session
from src.base_honeypot import BaseHoneypot
from mysql_mimic.errors import MysqlError, ErrorCode
import json
import logging
from pathlib import Path

# Load config
CONFIG_FILE = os.path.join(os.path.dirname(__file__),"honeypots", "mysql", "config.json")
with open(CONFIG_FILE, "r") as f:
    CONFIG = json.load(f)

# Set path to data.jsonl
DATA_FILE = os.path.join(os.path.dirname(__file__), "honeypots", "mysql", "data.jsonl")
logging.info(f"Using DATA_FILE path: {DATA_FILE}")

# Suppress noisy SQL syntax error logs
logging.getLogger("mysql_mimic.connection").addFilter(
    lambda record: "You have an error in your SQL syntax" not in record.getMessage()
)

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Set up Bedrock client
bedrock_client = boto3.client('bedrock-runtime', region_name='us-west-2')  # Adjust your region if needed


class StaticQueryHandler:
    def __init__(self, responses=None):
        self.responses = responses or {}

    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        logger.info(f"Received query: {sql}")
        sql = sql.upper().strip()
        return self.responses.get(sql, ([], ["empty_response"]))


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
    def __init__(self, *args, **kwargs):
        # Skip the initialization if the environment variable is set
        if os.environ.get("DISABLE_MYSQL_SESSION") == "1":
            logger.info("Skipping MySQL session initialization due to environment setting.")
            return
        super().__init__(*args, **kwargs)

        # Load LLM Config from MySQL honeypot config file
        self.config_file = Path(__file__).parent / "honeypots" / "mysql" / "config.json"
        self.config = self.load_config(self.config_file)

        # Set model_id and system_prompt from config file
        self.model_id = self.config.get("model_id", "default_model_id")
        self.system_prompt = self.config.get("system_prompt", "You are a MySQL server emulator. Only output valid MySQL query results formatted in JSON.")

        # Set data.jsonl path
        self.data_file = Path(__file__).parent / "honeypots" / "mysql" / "data.jsonl"
        self.data_file.parent.mkdir(parents=True, exist_ok=True)

        # Load cache
        self.query_response_cache = self.load_existing_data()

    def load_config(self, config_file: Path):
        """Loads configuration from the given JSON file."""
        try:
            with open(config_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config file {config_file}: {e}")
            return {}

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
        """
        Returns the LLM-generated response for the SQL query.
        Parses the response and handles errors gracefully.
        """
        try:
            # Fetch the raw response from the LLM (using the previously created method)
            response = await self.get_or_generate_response(query)
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

    async def handle_query(self, sql: str, attrs) -> Tuple[List[Tuple], List[str]]:
        logger.info(f"Handling query: {sql}")
        sql = sql.strip()

        # Custom hardcoded responses
        if attrs.get("user") == "attacker":
            raise MysqlError("You have an error in your SQL syntax", ErrorCode.PARSE_ERROR)

        if sql.upper() == "SELECT 1":
            return [("1",)], ["1"]
        elif sql.upper() == "SHOW DATABASES":
            return [("testdb",)], ["Database"]
        elif sql.upper() == "INVALID QUERY":
            raise MysqlError("You have an error in your SQL syntax", ErrorCode.PARSE_ERROR)

        try:
            response_json = await self.get_or_generate_response(sql)
            rows, columns = _parse_llm_response(response_json)

            # If LLM returned empty response, raise a parse error
            if not rows and not columns:
                logger.warning("LLM response contains no rows or columns.")
                raise MysqlError("You have an error in your SQL syntax", ErrorCode.PARSE_ERROR)

            return rows, columns

        except Exception as e:
            logger.error(f"Error handling query: {e}")
            raise MysqlError("You have an error in your SQL syntax", ErrorCode.PARSE_ERROR)

    async def get_or_generate_response(self, query: str) -> str:
        from src.llm_utils import invoke_llm, is_bedrock_accessible

        query = query.strip()
        if query in self.query_response_cache:
            logger.info(f"Query found in cache: {query}")
            return json.dumps(self.query_response_cache[query])

        # Check if Bedrock is accessible and raise an exception if it's not
        if not is_bedrock_accessible():
            raise Exception("Bedrock is not accessible. Cannot generate LLM response.")

        try:
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
    def __init__(self, port: int = None, identity_provider=None):
        super().__init__(port)
        self.identity_provider = identity_provider or AllowAllIdentityProvider()
        self.server = MysqlServer(
            port=self.port,
            session_factory=MySession,
            identity_provider=self.identity_provider,

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
