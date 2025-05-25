import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime

from honeypot_utils import allocate_port


class HoneypotSession(dict):
    """
    Honeypot session info, which holds the session id and other information based on past session operations.
    For example, it can hold the user info, the current directory, and other state-related information.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "session_id" not in self:
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

    def honeypot_type(self) -> str:
        """
        :return: the type of the honeypot, for example, "HTTP", "SSH", etc.
        """
        return self.__class__.__name__

    def log_data(self, session: HoneypotSession, data: dict):
        """

        :param session:
        :param data:
        """
        data_to_log = {
            "dd-honeypot": True,
            "time": datetime.now().isoformat(),
            "session-id": session.get("session_id"),
            "type": self.honeypot_type(),
        }
        data_to_log.update(data)
        print(json.dumps(data_to_log))
