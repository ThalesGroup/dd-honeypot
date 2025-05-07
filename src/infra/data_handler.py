import os
import json
from typing import Dict
from src.llm_utils import invoke_llm
import logging

logger = logging.getLogger(__name__)

class DataHandler:
    def __init__(self, data_file, system_prompt, model_id, invoke_fn=None):
        self.data_file = data_file
        self.system_prompt = system_prompt
        self.model_id = model_id
        self.invoke_fn = invoke_fn or invoke_llm

    def get_data(self, query: str) -> str:
        try:
            with open(self.data_file, "r") as f:
                for line in f:
                    item = json.loads(line)
                    if item["command"] == query:
                        return item["response"]
        except FileNotFoundError:
            pass

        logger.info(f"LLM fallback for command: {query}")
        response = self.invoke_fn(query, self.system_prompt, self.model_id)
        self._save_data(query, response)
        return response

    def _load_data(self) -> Dict[str, str]:
        if not os.path.exists(self.data_file):
            return {}
        with open(self.data_file, "r") as f:
            return {json.loads(line)["command"]: json.loads(line)["response"] for line in f if line.strip()}

    def _save_data(self, input_str: str, response: str):
        with open(self.data_file, "a") as f:
            f.write(json.dumps({"command": input_str, "response": response}) + "\n")
