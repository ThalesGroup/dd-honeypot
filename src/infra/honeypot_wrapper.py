import json
import logging
from pathlib import Path
from typing import Callable
from src.llm_utils import invoke_llm
from src.ssh_honeypot import SSHHoneypot
from src.mysql_honeypot import MySqlMimicHoneypot
logger = logging.getLogger(__name__)



def create_honeypot(config: dict, command_handler=None):
    honeypot_type = config["type"]
    data_file = Path(config["data_file"])
    system_prompt = config.get("system_prompt", "You are a server emulator.")
    model_id = config.get("model_id", "anthropic.claude-3-5-sonnet-20240620-v1:0")

    # If no external handler is passed, build the default
    if command_handler is None:
        command_handler = build_command_handler(data_file, system_prompt, model_id)

    if honeypot_type == "ssh":
        return SSHHoneypot(port=config.get("port", 0), command_handler=command_handler)
    elif honeypot_type == "mysql":
        return MySqlMimicHoneypot(port=config.get("port", 3306), command_handler=command_handler)
    else:
        raise ValueError(f"Unsupported honeypot type: {honeypot_type}")


def build_command_handler(data_file: Path, system_prompt: str, model_id: str) -> Callable[[str], str]:
    # Load command responses from the data file
    command_data = []
    if data_file.exists():
        with open(data_file, "r") as f:
            for line in f:
                if line.strip():
                    command_data.append(json.loads(line))

    # Command handler that falls back to LLM if no preconfigured response
    def handler(command: str) -> str:
        for entry in command_data:
            if entry["command"] == command:
                return entry["response"]

        # Fallback to invoking LLM if no response found
        logger.info(f"LLM fallback for command: {command}")
        user_prompt = f"The user entered: {command}"
        response = invoke_llm(system_prompt, user_prompt, model_id)

        # Add new response to the data file
        command_data.append({"command": command, "response": response})
        with open(data_file, "w") as f:
            for entry in command_data:
                f.write(json.dumps(entry) + "\n")

        return response

    return handler
