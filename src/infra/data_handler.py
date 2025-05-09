import json
import logging
from pathlib import Path
from typing import Optional, List

from src.infra.interfaces import HoneypotAction, HoneypotSession
from src.llm_utils import invoke_llm


class DataHandler(HoneypotAction):
    def __init__(
        self,
        data_file: str,
        system_prompt: str,
        model_id: str,
        invoke_fn=invoke_llm
    ):
        self.data_file = Path(data_file)
        self.system_prompt = system_prompt
        self.model_id = model_id
        self.invoke_fn = invoke_fn

        self.commands = self._load_data()

    def _load_data(self) -> List[dict]:
        if not self.data_file.exists():
            return []
        with self.data_file.open("r") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _save_data(self) -> None:
        with self.data_file.open("w") as f:
            for cmd in self.commands:
                f.write(json.dumps(cmd) + "\n")

    def connect(self, auth_info: dict) -> HoneypotSession:
        # Log the connection (could be extended)
        logging.info(f"DataHandler.connect: {auth_info}")
        return HoneypotSession()

    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        logging.info(f"DataHandler.query: {query}")

        # 1. Try to find the command in existing data
        for entry in self.commands:
            if entry["command"] == query:
                return entry["response"]

        # 2. Otherwise, fall back to LLM
        logging.info(f"LLM fallback for query: {query}")
        response = self.invoke_fn(self.system_prompt, query, self.model_id)

        # 3. Save new response and return
        self.commands.append({"command": query, "response": response})
        self._save_data()
        return response