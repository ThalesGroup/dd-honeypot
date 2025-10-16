import json
import logging
import os

from pathlib import Path
from typing import List, Optional

from honeypot_utils import normalize_backend_name
from infra.data_store import SqliteDataStore, DataStore
from infra.interfaces import HoneypotAction, HoneypotSession
from llm_utils import invoke_llm, InvokeLimiter


class DataHandler(HoneypotAction):
    def __init__(
        self,
        data_file: str,
        system_prompt: str,
        model_id: str,
        structure: dict = None,
        routes: list[dict] = None,
    ):
        data_folder = str(Path(data_file).parent.absolute())
        self._data_store = self._create_data_store(data_folder, structure)
        if os.path.exists(data_file):
            self._data_store.load_static_content(data_file)
        self._hints_file = Path(data_file.replace("data", "hints"))
        if isinstance(system_prompt, list):
            system_prompt = "\n".join(system_prompt)
        self._system_prompt = system_prompt
        self._model_id = model_id
        self._data_file = data_file
        self.entries = self._load_data_entries(data_file)
        self._hints = self._load_hints()
        self._limiter = InvokeLimiter(20, 600)
        self._routes = routes or []

    def _load_data_entries(self, path):
        entries = []
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line))
        return entries

    @staticmethod
    def _create_data_store(data_folder: str, structure: dict) -> DataStore:
        return SqliteDataStore(
            os.path.join(data_folder, "data_store.db"),
            structure if structure else {"command": "TEXT"},
        )

    def _load_hints(self) -> List[dict]:
        if not self._hints_file.exists():
            return []
        with self._hints_file.open("r") as f:
            return [json.loads(line) for line in f if line.strip()]

    def connect(self, auth_info: dict) -> HoneypotSession:
        # Log the connection (could be extended)
        logging.info(f"DataHandler.connect: {auth_info}")
        session = HoneypotSession()
        for key in auth_info:
            session[key] = auth_info[key]
        return session

    def invoke_llm_with_limit(self, user_prompt: str) -> (bool, str):
        if self._limiter.can_invoke("visitor"):
            response = invoke_llm(self._system_prompt, user_prompt, self._model_id)
            return True, response
        else:
            return False, "Internal error. Please try again later."

    def query(self, query: str, session: HoneypotSession, **kwargs) -> dict:
        return self.request({"command": query}, session, **kwargs)

    # noinspection PyPackageRequirements,PyMethodMayBeStatic
    def query_user_prompt(self, query: str, session: HoneypotSession) -> str:
        return f"User input: {query}"

    def request_user_prompt(self, info: dict) -> str:
        return f"User input: {info}"

    def user_prompt_hint(self, info: dict) -> Optional[str]:
        for entry in self._hints:
            if entry["path"] == info["path"] and entry["args"] == info["args"]:
                return entry["content"]
        return None

    def request(self, info: dict, session: HoneypotSession, **kwargs) -> dict:
        result = self._data_store.search(info)
        if result:
            logging.info(f"DataHandler.request: Found cached response for {info}")
            return {"output": result}

        invoked, response = self.invoke_llm_with_limit(self.request_user_prompt(info))
        if invoked:
            # Always store raw string
            self._data_store.store(info, response)
        return {"output": response}

    def dispatch(
        self, query_input: dict, session: HoneypotSession
    ) -> str | dict | None:
        """
        Decide which backend to use for dispatcher mode.
        Returns:
          - backend name (normalized) present in query_input["honeypots"], or
          - dict override {"status","headers","body"} to short-circuit, or
          - None (caller will apply defaults)
        """
        # Normalize key
        key = (query_input.get("routing_key") or "/").lower().rstrip("/") or "/"
        routes = sorted(
            self._routes,
            key=lambda r: len((r.get("path") or "").rstrip("/").lower()),
            reverse=True,
        )

        # Try route matches
        for r in routes:
            p = (r.get("path") or "").lower().rstrip("/") or "/"
            is_root = p == "/" and key == "/"
            is_bound = p != "/" and (key == p or key.startswith(p + "/"))
            if is_root or is_bound:
                name = normalize_backend_name(r.get("name") or "")
                # Allow "UNKNOWN" to fall back to first available
                if name == "unknown":
                    break
                return name if name else None

        # Default to first available backend if provided
        hps = query_input.get("honeypots") or []
        if hps:
            # query_input["honeypots"] are already normalized by the caller (dispatcher wiring)
            return hps[0]
        return None
