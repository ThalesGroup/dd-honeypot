import json
import logging
import os
from pathlib import Path

from base_honeypot import BaseHoneypot
from http_data_handlers import HTTPDataHandler
from http_honeypot import HTTPHoneypot
from infra.data_handler import DataHandler
from tcp_honeypot import TCPHoneypot

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
    fs_file = config.get("fs_file")

    if not data_file.exists():
        data_file.parent.mkdir(parents=True, exist_ok=True)
        data_file.touch()

    if honeypot_type == "http":
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
        )

    # For SSH, we optionally chain with fake filesystem
    if honeypot_type == "ssh":
        from ssh_honeypot import SSHHoneypot
        from infra.fake_fs_data_handler import FakeFSDataHandler
        from infra.chained_data_handler import ChainedDataHandler

        if fs_file:
            fs_handler = FakeFSDataHandler(
                data_file=str(data_file),
                system_prompt=system_prompt,
                model_id=model_id,
                fs_file=fs_file,
            )
            llm_handler = DataHandler(
                data_file=str(data_file), system_prompt=system_prompt, model_id=model_id
            )
            action = ChainedDataHandler(
                fakefs_handler=fs_handler, llm_handler=llm_handler
            )
        else:
            action = DataHandler(
                data_file=str(data_file), system_prompt=system_prompt, model_id=model_id
            )

        return SSHHoneypot(port=port, action=action)

    elif honeypot_type == "http":
        return HTTPHoneypot(port=port, action=action, name=config.get("name"))

    elif honeypot_type == "tcp":
        return TCPHoneypot(port=port, action=action, name=config.get("name"))

    elif honeypot_type == "mysql":
        from mysql_honeypot import MySqlMimicHoneypot

        return MySqlMimicHoneypot(port=port, action=action)

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
