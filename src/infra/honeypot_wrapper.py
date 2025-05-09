import json
import logging
from pathlib import Path

from src.infra.data_handler import DataHandler
from src.ssh_honeypot import SSHHoneypot
# from src.mysql_honeypot import MySqlMimicHoneypot  # Uncomment when you have MySQL implementation

logger = logging.getLogger(__name__)


def create_honeypot(config: dict, invoke_fn=None):
    """
    Create a honeypot from a config dictionary.
    Expected keys: type, data_file, model_id, system_prompt, port
    """
    honeypot_type = config["type"]
    data_file = Path(config["data_file"])
    model_id = config.get("model_id", "anthropic.claude-3-5-sonnet-20240620-v1:0")
    system_prompt = config.get("system_prompt", "You are a server emulator.")
    port = config.get("port", 0)

    # Create a shared action handler (implements HoneypotAction)
    action = DataHandler(
        data_file=str(data_file),
        system_prompt=system_prompt,
        model_id=model_id,
        invoke_fn=invoke_fn
    )

    # Build protocol-specific honeypot
    if honeypot_type == "ssh":
        return SSHHoneypot(port=port, action=action)

    elif honeypot_type == "mysql":
        raise NotImplementedError("MySQL honeypot is not yet integrated with action-based design.")
        # return MySqlMimicHoneypot(port=port, action=action)

    else:
        raise ValueError(f"Unsupported honeypot type: {honeypot_type}")


def create_honeypot_from_file(file_path: str):
    """
    Load honeypot config from a JSON file and call create_honeypot
    """
    with open(file_path, "r") as f:
        config = json.load(f)
    return create_honeypot(config)