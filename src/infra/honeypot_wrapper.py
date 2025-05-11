import json
import logging
from pathlib import Path

from http_data_handlers import HTTPDataHandler
from http_honeypot import HTTPHoneypot
from src.infra.data_handler import DataHandler
from src.ssh_honeypot import SSHHoneypot
from src.mysql_honeypot import MySqlMimicHoneypot

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
        return SSHHoneypot(port=port, action=action)
    elif honeypot_type == "mysql":
        return MySqlMimicHoneypot(port=port, action=action)
    elif honeypot_type == "phpMyAdmin":
        return HTTPHoneypot(port=port, action=action)
    else:
        raise ValueError(f"Unsupported honeypot type: {honeypot_type}")


def create_honeypot_from_file(file_path: str):
    """
    Load honeypot config from a JSON file and call create_honeypot
    """
    with open(file_path, "r") as f:
        config = json.load(f)
    return create_honeypot(config)
