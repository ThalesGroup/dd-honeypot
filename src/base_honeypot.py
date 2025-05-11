import uuid
from abc import ABC, abstractmethod

from honeypot_utils import allocate_port


class HoneypotSession(dict):
    """
    Honeypot session info, which holds the session id and other information based on past session operations.
    For example, it can hold the user info, the current directory, and other state-related information.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self["session_id"] = str(uuid.uuid4())

    @property
    def session_id(self):
        return self["session_id"]


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

    # noinspection PyMethodMayBeStatic
    def is_running(self) -> bool:
        """

        :return: True if the honeypot is running, False otherwise
        """
        return True
