import logging
import threading
import uuid
from abc import ABC, abstractmethod
from typing import Optional

from mysql_mimic.server import MysqlServer
from mysql_mimic.connection import Connection
from mysql_mimic.session import Session
from mysql_mimic.control import LocalControl
from mysql_mimic.packets import make_error
from src.honeypot_utils import allocate_port

logger = logging.getLogger(__name__)


class HoneypotSession:
    """
    Honeypot session info, which holds the session ID and other state-related information.
    """

    def __init__(self):
        self.__session_id = str(uuid.uuid4())
        self.__info = {}

    @property
    def session_id(self) -> str:
        return self.__session_id

    @property
    def info(self) -> dict:
        return self.__info


class BaseHoneypot(ABC):
    """
    Abstract base class for honeypots using mysql_mimic for MySQL behavior.
    """

    def __init__(self, port: int = None):
        super().__init__()
        self.__port = port if port else allocate_port()
        logger.info(f"Allocated port {self.__port} for honeypot")

        self.server = None
        self.thread = None

    @property
    def port(self) -> int:
        """
        :return: Port number the honeypot listens on
        """
        return self.__port

    @abstractmethod
    def start(self):
        """
        Start the honeypot. After this is called, the honeypot should be listening and active.
        """
        raise NotImplementedError("Honeypot start() not implemented")

    @abstractmethod
    def stop(self):
        """
        Stop the honeypot and clean up resources.
        """
        raise NotImplementedError("Honeypot stop() not implemented")

    def connect(self, auth_info: dict) -> Optional[HoneypotSession]:
        """
        Authenticate to the honeypot. This base implementation ignores credentials and always accepts.
        :param auth_info: Dict containing authentication information (username, password, etc.)
        :return: A new HoneypotSession
        """
        logger.info(f"Connection attempt with auth_info={auth_info} — accepted")
        return HoneypotSession()

    def query(self, query: str, session: HoneypotSession, **kwargs) -> list:
        """
        Execute a query on the honeypot. Use the Connection and Session classes for processing.
        :param query: The query to execute
        :param session: Honeypot session context
        :return: Result of the query
        """
        logger.info(f"Query received: {query}")

        # Simulate query processing using MySQL mimic connection and session
        try:
            # Create a connection object with necessary parameters
            connection = Connection(
                stream=None,  # Assuming no actual stream for this simulation
                session=Session(),
                control=LocalControl(),  # You can add more control features if needed
                server_capabilities=None,  # Set appropriate capabilities
                identity_provider=None,  # Optional: Implement identity provider if necessary
                ssl=None  # SSL can be added if required
            )

            # Simulate processing the query (this can be extended as needed)
            # For example, check if the query is a SELECT or an INSERT
            if "SELECT" in query.upper():
                return [{"column1": "value1", "column2": "value2"}]  # Example result for SELECT query
            elif "INSERT" in query.upper():
                return [{"status": "OK", "message": "Query executed successfully"}]  # Example for INSERT

            # You can handle different queries here as per your need
            return [{"status": "OK", "message": "Query processed"}]

        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return [make_error()]

    def request(self, info: dict, session: HoneypotSession, **kwargs) -> dict:
        """
        Execute a request on the honeypot. This method can be customized to process requests.
        :param info: Request details
        :param session: Honeypot session context
        :return: Response dictionary
        """
        logger.info(f"Request received: {info}")

        # Simulate request handling here (e.g., handling HTTP requests or MySQL command requests)
        # This can be extended to include specific logic for different types of requests.
        return {"status": "OK", "message": "Request processed successfully"}
