import json
import logging
import os.path
from pathlib import Path

from base_honeypot import BaseHoneypot
from http_data_handlers import HTTPDataHandler
from http_honeypot import HTTPHoneypot
from infra.data_handler import DataHandler

logger = logging.getLogger(__name__)

_DEFAULT_MODEL_ID = "anthropic.claude-instant-v1"


def create_honeypot(config: dict, invoke_fn=None):
    """
    Create a honeypot from a config dictionary.
    Expected keys: type, data_file, model_id, system_prompt, port
    """
    if "type" not in config:
        raise ValueError("Honeypot 'type' must be specified.")
    honeypot_type = config["type"]
    data_file = Path(config.get("data_file", "/dev/null"))
    model_id = config.get("model_id", _DEFAULT_MODEL_ID)
    system_prompt = config.get("system_prompt", "You are a server emulator.")
    port = config.get("port", 0)
    if honeypot_type == "phpMyAdmin":
        action = HTTPDataHandler(
            data_file=str(data_file),
            system_prompt=system_prompt,
            model_id=model_id,
        )
    else:
        action = DataHandler(
            data_file=str(data_file),
            system_prompt=system_prompt,
            model_id=model_id,
            invoke_fn=invoke_fn,
        )

    # Build protocol-specific honeypot
    if honeypot_type == "ssh":
        from ssh_honeypot import SSHHoneypot

        return SSHHoneypot(port=port, action=action)
    elif honeypot_type == "mysql":
        from mysql_honeypot import MySqlMimicHoneypot

        return MySqlMimicHoneypot(port=port, action=action)
    elif honeypot_type == "phpMyAdmin":
        return HTTPHoneypot(port=port, action=action)
    else:
        raise ValueError(f"Unsupported honeypot type: {honeypot_type}")


def create_honeypot_by_folder(folder_path: str) -> BaseHoneypot:
    """
    Load honeypot by a folder containing honeypot configuration and data
    """
    with open(os.path.join(folder_path, "config.json")) as f:
        config = json.load(f)
    config["data_file"] = os.path.join(folder_path, "data.jsonl")
    return create_honeypot(config)
