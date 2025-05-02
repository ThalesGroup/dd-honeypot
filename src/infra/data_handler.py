import os
import json
from typing import Dict
from src.llm_utils import invoke_llm

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
        with open(self.data_file, "r") as f:
            return {json.loads(line)["command"]: json.loads(line)["response"] for line in f if line.strip()}

    def get_data(self, input_str: str, user_prompt: str) -> str:
        if input_str in self.data:
            return self.data[input_str]
        if input_str in self.cache:
            return self.cache[input_str]

        response = invoke_llm(self.system_prompt, user_prompt, self.model_id)
        self.cache[input_str] = response
        self.data[input_str] = response
        self._save_data(input_str, response)
        return response

    def _save_data(self, input_str: str, response: str):
        with open(self.data_file, "a") as f:
            f.write(json.dumps({"command": input_str, "response": response}) + "\n")
