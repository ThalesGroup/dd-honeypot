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

    def get_data(self, input_str, user_prompt):
        # Check cache first
        if input_str in self.cache:
            return self.cache[input_str]  # Return cached response

        # If not cached, check if the data exists in the file
        data = self._read_data_from_file(input_str)
        if data:
            response = data.get('response', 'No data available')
        else:
            # Fallback to LLM if not found in the file
            response = llm_utils.invoke_llm(self.system_prompt, user_prompt, self.model_id)

            # Extract the first string from the LLM response (from the 'columns' list)
            if isinstance(response, dict) and "columns" in response:
                response = response["columns"][0]  # Assuming the first column holds the actual response string

        # Cache and return the string response
        self.cache[input_str] = response
        return response

    def _read_data_from_file(self, input_str):
        # Read the data file to check for matching command
        try:
            with open(self.data_file, 'r') as file:
                for line in file:
                    data = json.loads(line)
                    if data.get("command") == input_str:
                        return data
        except FileNotFoundError:
            return None
        return None

     # Extract the string from the LLM response
    def _save_data(self, input_str: str, response: str):
        with open(self.data_file, "a") as f:
            f.write(json.dumps({"command": input_str, "response": response}) + "\n")

