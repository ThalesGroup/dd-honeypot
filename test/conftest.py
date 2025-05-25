import json
import os


def get_honeypots_folder() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypots")


def get_honeypot_folder(name: str) -> str:
    return os.path.join(get_honeypots_folder(), name)


def get_config(name: str) -> dict:
    conf_file = os.path.join(get_honeypots_folder(), name, f"config.json")
    return json.load(open(conf_file))
