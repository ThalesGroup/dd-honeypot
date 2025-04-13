import uuid
import logging
from abc import ABC, abstractmethod
from typing import Optional

from src.honeypot_utils import allocate_port

logger = logging.getLogger(__name__)


class HoneypotSession:
    """
    Honeypot session info, which holds the session ID and other state-related information,
    like user context, current working directory.
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
    Abstract base class for honeypots. Defines the basic interface and common functionality.
    """

    def __init__(self, port: int = None):
        super().__init__()
        self.__port = port if port else allocate_port()
        logger.info(f"Allocated port {self.__port} for honeypot")

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
        Execute a query on the honeypot. Override in subclass if query support is needed.
        :param query: The query to execute
        :param session: Honeypot session context
        :return: Result of the query
        """
        logger.warning("query() called but not implemented in this honeypot")
        raise NotImplementedError("query() not implemented")

    def request(self, info: dict, session: HoneypotSession, **kwargs) -> dict:
        """
        Execute a request on the honeypot. E.g., HTTP request, shell command.
        :param info: Request details
        :param session: Honeypot session context
        :return: Response dictionary
        """
        logger.warning("request() called but not implemented in this honeypot")
        raise NotImplementedError("request() not implemented")
