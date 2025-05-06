import os
import json
from typing import Dict

from pip._internal.cli.main import logger

from src import llm_utils
import logging

logger = logging.getLogger(__name__)


class DataHandler:
    def __init__(self, data_file: str, system_prompt: str, model_id: str):
        self.data_file = data_file
        self.system_prompt = system_prompt
        self.model_id = model_id
        self.cache: Dict[str, str] = {}
        self.data = self._load_data()

    def _load_data(self) -> Dict[str, str]:
        if not os.path.exists(self.data_file):
            return {}
        result = {}
        with open(self.data_file, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    key = item.get("command") or item.get("query")
                    response = item.get("response")
                    if key and response:
                        result[key.strip()] = response
                except Exception as e:
                    logger.warning(f"Skipping invalid line in data file: {e}")
        return result

    def get_data(self, input_str: str, user_prompt: str) -> dict:
        # Check existing data cache
        response = self.data.get(input_str) or self.cache.get(input_str)

        # If no response cached, invoke LLM
        if not response:
            response = llm_utils.invoke_llm(self.system_prompt, user_prompt, self.model_id)
            self.cache[input_str] = response
            self.data[input_str] = response
            self._save_data(input_str, response)

        # Ensure consistent return format (for MySQL honeypot)
        if isinstance(response, dict) and "columns" in response and "rows" in response:
            return response
        else:
            return {"columns": ["No data available"], "rows": []}

    def _save_data(self, input_str: str, response: str):
        with open(self.data_file, "a") as f:
            f.write(json.dumps({"command": input_str, "response": response}) + "\n")

