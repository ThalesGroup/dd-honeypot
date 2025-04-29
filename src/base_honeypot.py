import uuid
from abc import ABC, abstractmethod
from typing import Optional

from src.honeypot_utils import allocate_port

class HoneypotSession:
    """
    Honeypot session info, which holds the session id and other information based on past session operations.
    For example, it can hold the user info, the current directory, and other state-related information.
    """

    def __init__(self):
        self.__session_id = str(uuid.uuid4())
        self.__info = {}

    @property
    def session_id(self):
        return self.__session_id

    @property
    def info(self):
        return self.__info

    def set_info(self, key, value):
        #Method to safely set information in the session.
        self.__info[key] = value

    def get_info(self, key):
        """Method to safely get information from the session."""
        return self.__info.get(key)

    def __contains__(self, key):
        """Check if a key exists in the session info."""
        return key in self.__info



class BaseHoneypot(ABC):

    def __init__(self, port: int = None):
        super().__init__()
        self.__port = port if port else allocate_port()

    @property
    def port(self):
        """
        :return: port number
        """
        return self.__port

    @abstractmethod
    def start(self):
        """
        Start the honeypot, after this method is called, the honeypot should be running and listening on the given port
        """
        raise NotImplementedError()

    @abstractmethod
    def stop(self):
        """
        Stop the honeypot and release all resources
        """
        raise NotImplementedError()

    # noinspection PyMethodMayBeStatic,PyUnusedLocal
    def connect(self, auth_info: dict) -> Optional[HoneypotSession]:
        """
        authenticate to the honeypot
        :param auth_info: authentication information, can be username and password, or other information used
        for authentication
        :return: True if authentication is successful, False otherwise
        """
        return HoneypotSession()

    def query(self, query: str, session: HoneypotSession, **kwargs) -> list:
        """
        execute a query on the honeypot, for honeypots which support queries
        :param query:  to execute
        :param session: honeypot session context
        :return: result of the query
        """
        raise NotImplementedError()

    def request(self, info: dict, session: HoneypotSession, **kwargs) -> dict:
        """
        execute a request on the honeypot. Request can be for example an HTTP request, or a command to execute
        :param info: request information
        :param session: honeypot session context
        :return: response of the request
        """
        raise NotImplementedError()