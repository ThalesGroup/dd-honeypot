import json
import logging
import os
import random
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from honeypot_utils import allocate_port

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from infra.interfaces import HoneypotAction


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
    def __init__(
        self,
        port: int = None,
        config: dict = None,
        inprocess_backends: Optional[dict] = None,
    ):
        super().__init__()
        self._action = None
        self.__port = port if port else allocate_port()
        self.__config = config or {}
        self.is_dispatcher = bool(self.config.get("is_dispatcher"))
        self._session_map: dict[str, str] = {}
        self._inprocess_backends: Optional[dict[str, "BaseHoneypot"]] = (
            {k: v for k, v in (inprocess_backends or {}).items()}
            if inprocess_backends
            else None
        )

    @property
    def action(self) -> "HoneypotAction":
        return self._action

    @action.setter
    def action(self, value: "HoneypotAction"):
        self._action = value

    @property
    def port(self):
        """
        :return: port number
        """
        return self.__port

    @port.setter
    def port(self, value: int):
        """
        Set the port_number
        :param value: port number
        """
        self.__port = value

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

    def forward_to_backend(self, backend_name: str, ctx: dict):

        if self._inprocess_backends:
            backend = self._inprocess_backends.get(
                backend_name
            ) or self._inprocess_backends.get("UNKNOWN")
            if not backend:
                return 500, {"Content-Type": "text/plain"}, b"Unknown backend"
            return backend.handle_request(ctx)
        try:
            handler = BaseHoneypot.get_honeypot_by_name(backend_name)
            return handler.handle_request(ctx)
        except KeyError:
            return 500, {"Content-Type": "text/plain"}, b"Unknown backend"

    def dispatch(self, ctx: dict) -> tuple[int, dict, str | bytes]:
        session_id = ctx.get("session_id") or str(uuid.uuid4())
        routing_key = (ctx.get("routing_key") or "/").lower()
        meta = ctx.get("meta") or {}

        if self.action and hasattr(self.action, "dispatch"):
            try:
                choice = self.action.dispatch(
                    {
                        "routing_key": routing_key,
                        "meta": meta,
                        "honeypots": [],
                    },
                    HoneypotSession(session_id=session_id),
                )
                if isinstance(choice, dict) and {"status", "headers", "body"} <= set(
                    choice
                ):
                    return (
                        choice["status"],
                        choice.get("headers", {}),
                        choice.get("body", ""),
                    )
                if isinstance(choice, str):
                    self._session_map[session_id] = choice
                    return self.forward_to_backend(choice, ctx)
            except Exception as e:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Exception in action.dispatch: {e}")

        pinned = self._session_map.get(session_id)
        if pinned:
            return self.forward_to_backend(pinned, ctx)

        from honeypot_registry import get_honeypot_registry

        registry = get_honeypot_registry()
        names = registry.get_honeypot_names()
        if names:
            name = random.choice(names)
            self._session_map[session_id] = name
            return self.forward_to_backend(name, ctx)

        return 502, {"Content-Type": "text/plain"}, b"Bad Gateway"

    @staticmethod
    def get_honeypot_by_name(name: str):
        from honeypot_registry import get_honeypot_registry

        return get_honeypot_registry().get_honeypot(name)

    def handle_request(self, ctx: dict) -> tuple:
        raise NotImplementedError("handle_request must be implemented by subclasses")
