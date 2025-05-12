import json
import logging
import os
from pathlib import Path

from base_honeypot import BaseHoneypot
from http_data_handlers import HTTPDataHandler
from http_honeypot import HTTPHoneypot
from infra.data_handler import DataHandler

logger = logging.getLogger(__name__)


def create_honeypot(config: dict) -> BaseHoneypot:
    """
    Create a honeypot from a config dictionary.
    Required keys: type, data_file, model_id, system_prompt, port
    """

    required_keys = ["type", "data_file", "model_id", "system_prompt", "port"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

    honeypot_type = config["type"]
    data_file = Path(config["data_file"])
    model_id = config["model_id"]
    system_prompt = config["system_prompt"]
    port = config["port"]

    # Ensure data file exists
    if not data_file.exists():
        data_file.parent.mkdir(parents=True, exist_ok=True)
        data_file.touch()

    # Choose appropriate handler
    if honeypot_type == "phpMyAdmin":
        action = HTTPDataHandler(data_file=str(data_file), system_prompt=system_prompt, model_id=model_id)
    else:
        action = DataHandler(data_file=str(data_file), system_prompt=system_prompt, model_id=model_id)

    # Create the appropriate honeypot instance
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
    Load honeypot configuration and data from a folder.
    Assumes folder contains config.json and data.jsonl
    """
    config_path = os.path.join(folder_path, "config.json")
    data_file_path = os.path.join(folder_path, "data.jsonl")

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Missing config.json in {folder_path}")

    with open(config_path) as f:
        config = json.load(f)

    config["data_file"] = data_file_path
    return create_honeypot(config)