import json
import os
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

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

    def __init__(self, port: int = None, config: dict = None):
        super().__init__()
        self.__port = port if port else allocate_port()
        self.__config = config

    @property
    def port(self):
        """
        :return: port number
        """
        return self.__port

    @property
    def name(self) -> Optional[str]:
        """
        :return: name of the honeypot
        """
        return self.__config.get("name") if self.__config else None

    @property
    def config(self) -> Optional[dict]:
        """
        :return: name of the honeypot
        """
        return self.__config

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

    def log_login(self, session: HoneypotSession, data: dict):
        """
        log login data for the honeypot session. This can be used to log user login attempts, successful logins,
        :param session:
        :param data:
        """
        self.log_data(session, {"login": data})

    def log_data(self, session: HoneypotSession, data: dict):
        """
        log data for the honeypot session. This can be used to log user commands, requests, and other data.
        :param session:
        :param data:
        """
        data_to_log = {
            "dd-honeypot": True,
            "region": os.getenv("AWS_DEFAULT_REGION"),
            "time": datetime.now().isoformat(),
            "session-id": session.get("session_id"),
            "type": self.honeypot_type(),
            "name": self.name,
        }
        data_to_log.update(data)
        print(json.dumps(data_to_log))
