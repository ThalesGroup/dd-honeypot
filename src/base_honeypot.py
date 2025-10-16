import json
import os
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from honeypot_utils import allocate_port

if TYPE_CHECKING:
    from infra.interfaces import HoneypotAction


class HoneypotSession(dict):
    """
    Honeypot session info, which holds the session id and other information based on past session operations.
    For example, it can hold the user info, the current directory, and other state-related information.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.active_honeypot: Optional[str] = None
        if "session_id" not in self:
            self["session_id"] = str(uuid.uuid4())

    @property
    def session_id(self):
        return self["session_id"]


class BaseHoneypot(ABC):

    def __init__(self, port: int = None, config: dict = None):
        super().__init__()
        self._action = None
        self.__port = port if port else allocate_port()
        self.__config = config or {}
        self.config_dir: Optional[str] = self.__config.get("config_dir")
        self.is_dispatcher = bool(self.config.get("is_dispatcher"))
        self.dispatch_rules = []
        self._session_map: dict[str, str] = {}
        self._dispatch_backends: dict[str, callable] = {}

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

    def set_dispatch_backends(self, backends: dict[str, callable]) -> None:
        self.dispatch_backends = backends or {}

    def _load_dispatcher_rules(self) -> None:
        if not self.config_dir:
            self.dispatch_rules = []
            return
        for fname in ("dispatcher_data.jsonl", "data.jsonl"):
            p = os.path.join(self.config_dir, fname)
            if os.path.exists(p):
                rules = []
                with open(p, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rules.append(json.loads(line))
                        except OSError:
                            continue
                self.dispatch_rules = rules
                return
        self.dispatch_rules = []

    def _normalize_name(self, raw) -> str:
        """Normalize the name of the backend honeypot from the raw output of the LLM"""
        if isinstance(raw, dict):
            cand = raw.get("name") or raw.get("target") or raw.get("backend")
        else:
            cand = str(raw or "").strip()
        return cand.lower() if cand else ""

    def _match_rules(self, routing_key: str) -> Optional[str]:
        """Match the routing key against the dispatch rules and return the name of the backend honeypot if matched"""
        for r in self.dispatch_rules:
            path = r.get("path") or r.get("routing_key")
            name = r.get("name")
            if path is None or name is None:
                continue
            path_norm = str(path).rstrip("/").lower()
            key_norm = str(routing_key).rstrip("/").lower()
            if path_norm == "/":
                if key_norm == "/":
                    return name
            else:
                if key_norm == path_norm or key_norm.startswith(path_norm + "/"):
                    return name
        return None

    def _decide_backend(self, session_id: str, routing_key: str, meta: dict) -> str:
        """Decide which backend honeypot to forward the request to, based on the routing key and meta information"""
        hit = self._match_rules(routing_key) if self.dispatch_rules else None
        if hit and hit in self.dispatch_backends:
            self.session_map[session_id] = hit
            return hit

        if self.action:
            query_input = json.dumps(
                {
                    "routing_key": routing_key,
                    "meta": meta,
                    "honeypots": list(self.dispatch_backends),
                }
            )
            try:
                llm_out = self.action.query(
                    query_input, session=HoneypotSession(session_id=session_id)
                )
                name = self._normalize_name(llm_out)
                if name in self.dispatch_backends:
                    self.session_map[session_id] = name
                    return name
            except OSError:
                pass

        name = next(iter(self.dispatch_backends.keys()), "UNKNOWN")
        self.session_map[session_id] = name
        return name

    def _dispatch_handle(self, ctx):
        sid = self.session_map.get(ctx.session_id)
        key = self._decide_backend(sid, ctx.routing_key, ctx.meta)
        meta = ctx.meta or {}
        name = self.session_map.get(sid) or self._decide_backend(sid, key, meta)
        return self.forward_to_backend(name, ctx)

    def forward_to_backend(self, backend_name: str, ctx):
        if backend_name not in self.dispatch_backends:
            return 502, {"Content-Type": "text/plain"}, b"Bad Gateway"
        handler = self.dispatch_backends[backend_name]
        return handler(ctx)
