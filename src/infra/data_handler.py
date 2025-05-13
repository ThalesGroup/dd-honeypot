import json
import logging
from pathlib import Path
from typing import List, Optional

from infra.interfaces import HoneypotAction, HoneypotSession
from llm_utils import invoke_llm, InvokeLimiter


class DataHandler(HoneypotAction):
    def __init__(self, data_file: str, system_prompt: str, model_id: str):
        self.data_file = Path(data_file)
        self.hints_file = Path(data_file.replace("data", "hints"))
        self.system_prompt = system_prompt
        self.model_id = model_id
        self.commands = self._load_data()
        self.hints = self._load_hints()
        self._limiter = InvokeLimiter(20, 600)

    def _load_data(self) -> List[dict]:
        if not self.data_file.exists():
            return []
        with self.data_file.open("r") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _load_hints(self) -> List[dict]:
        if not self.hints_file.exists():
            return []
        with self.hints_file.open("r") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _save_data(self) -> None:
        with self.data_file.open("w") as f:
            for cmd in self.commands:
                f.write(json.dumps(cmd) + "\n")

    def connect(self, auth_info: dict) -> HoneypotSession:
        # Log the connection (could be extended)
        logging.info(f"DataHandler.connect: {auth_info}")
        session = HoneypotSession()
        for key in auth_info:
            session[key] = auth_info[key]
        return session

    def invoke_llm_with_limit(self, user_prompt: str) -> (bool, str):
        if self._limiter.can_invoke("visitor"):
            response = invoke_llm(self.system_prompt, user_prompt, self.model_id)
            return True, response
        else:
            return False, "Internal error. Please try again later."

    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        logging.info(f"DataHandler.query: {query}")

        # 1. Try to find the command in existing data
        for entry in self.commands:
            if entry["command"] == query:
                return entry["response"]

        # 2. Otherwise, fall back to LLM
        logging.info(f"LLM fallback for query: {query}")
        invoked, response = self.invoke_llm_with_limit(query)
        if invoked:
            # 3. Save new response and return
            self.commands.append({"command": query, "response": response})
            self._save_data()
        return response

    def user_prompt(self, info: dict) -> str:
        raise NotImplementedError()

    def user_prompt_hint(self, info: dict) -> Optional[str]:
        args = dict(info["request"].args)
        for entry in self.hints:
            if entry["path"] == info["path"] and entry["args"] == args:
                return entry["content"]
        return None

    def request(self, info: dict, session: HoneypotSession, **kwargs) -> str:
        args = dict(info["request"].args)
        for entry in self.commands:
            if entry["path"] == info["path"] and entry["args"] == args:
                return entry["content"]
        invoked, response = self.invoke_llm_with_limit(self.user_prompt(info))
        if invoked:
            self.commands.append(
                {"path": info["path"], "args": args, "content": response}
            )
            self._save_data()
        return response
