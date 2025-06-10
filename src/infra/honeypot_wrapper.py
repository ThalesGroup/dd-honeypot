import json
import logging
import os

from base_honeypot import BaseHoneypot
from http_data_handlers import HTTPDataHandler
from http_honeypot import HTTPHoneypot
from infra.File_download_handler import FileDownloadHandler
from infra.chain_honeypot_action import ChainedHoneypotAction
from infra.chained_data_handler import ChainedDataHandler
from infra.data_handler import DataHandler
from infra.fake_fs_data_handler import FakeFSDataHandler
from sql_data_handler import SqlDataHandler
from telnet_honeypot import TelnetHoneypot

logger = logging.getLogger(__name__)


def build_data_handler(config: dict, log_callback=None):
    data_file = str(config["data_file"])
    model_id = config["model_id"]
    system_prompt = config["system_prompt"]
    fs_file = config.get("fs_file")

    if fs_file:
        fakefs_handler = FakeFSDataHandler(
            data_file=data_file,
            system_prompt=system_prompt,
            model_id=model_id,
            fs_file=fs_file,
        )
        llm_handler = DataHandler(
            data_file=data_file,
            system_prompt=system_prompt,
            model_id=model_id,
        )
        file_download_handler = FileDownloadHandler(
            fakefs_handler=fakefs_handler, log_callback=log_callback
        )

        chained_handler = ChainedDataHandler(
            [file_download_handler, fakefs_handler, llm_handler]
        )

        return chained_handler

    else:
        return DataHandler(
            data_file=data_file,
            system_prompt=system_prompt,
            model_id=model_id,
        )


def create_honeypot(config: dict) -> BaseHoneypot:
    required_keys = ["type", "data_file", "model_id", "system_prompt", "port"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

    honeypot_type = config["type"]
    port = config["port"]

    if honeypot_type == "http":
        action = HTTPDataHandler(
            data_file=str(config["data_file"]),
            system_prompt=config["system_prompt"],
            model_id=config["model_id"],
        )
        return HTTPHoneypot(port=port, action=action, config=config)

    action = build_data_handler(config)

    if honeypot_type == "ssh":
        from ssh_honeypot import SSHHoneypot

        honeypot = SSHHoneypot(port=port, action=action, config=config)
        if isinstance(action, ChainedDataHandler):
            action.log_callback = honeypot.log_data
        return honeypot

    elif honeypot_type == "alpine":
        from ssh_honeypot import SSHHoneypot

        honeypot = SSHHoneypot(port=port, action=action, config=config)
        if isinstance(action, ChainedDataHandler):
            action.log_callback = honeypot.log_data
        return honeypot

    elif honeypot_type == "busybox":
        from ssh_honeypot import SSHHoneypot

        honeypot = SSHHoneypot(port=port, action=action, config=config)
        if isinstance(action, ChainedDataHandler):
            action.log_callback = honeypot.log_data
        return honeypot

    elif honeypot_type == "tcp":
        from tcp_honeypot import TCPHoneypot

        return TCPHoneypot(port=port, action=action, config=config)

    elif honeypot_type == "telnet":
        return TelnetHoneypot(port=port, action=action, config=config)

    elif honeypot_type == "mysql":
        from mysql_honeypot import MySQLHoneypot

        dialect = config.get("dialect")
        action = ChainedHoneypotAction(action, SqlDataHandler(dialect=dialect))
        return MySQLHoneypot(port=port, action=action, config=config)

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

    if "fs_file" in config:
        fs_file_candidate = os.path.join(
            folder_path, os.path.basename(config["fs_file"])
        )
        if os.path.exists(fs_file_candidate):
            config["fs_file"] = fs_file_candidate
        else:
            logging.warning(
                f"fs_file declared but not found: {fs_file_candidate}. Continuing without fakefs."
            )
            config.pop("fs_file")

    config["data_file"] = data_file_path
    return create_honeypot(config)
