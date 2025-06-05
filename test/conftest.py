import contextlib
import json
import os
import tempfile
import threading
from time import sleep
from typing import Generator

from honeypot_main import start_dd_honeypot
from honeypot_utils import allocate_port


def get_honeypots_folder() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypots")


def get_honeypot_folder(name: str) -> str:
    return os.path.join(get_honeypots_folder(), name)


def get_config(name: str) -> dict:
    conf_file = os.path.join(get_honeypots_folder(), name, f"config.json")
    return json.load(open(conf_file))


@contextlib.contextmanager
def get_honeypot_main(monkeypatch, honeypot_config: dict) -> Generator[int, None, None]:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("STOP_HONEYPOT", "false")
    port = allocate_port()
    honeypot_config["port"] = port
    if "name" not in honeypot_config:
        honeypot_config["name"] = f"test-main-{honeypot_config['type']}-honeypot"
    if "model_id" not in honeypot_config:
        honeypot_config["model_id"] = "test-model-id"
    if "system_prompt" not in honeypot_config:
        honeypot_config["system_prompt"] = ["You are a test honeypot"]
    with tempfile.TemporaryDirectory() as tmpdir:
        json.dump(
            honeypot_config,
            open(os.path.join(tmpdir, "config.json"), "w"),
        )
        t = threading.Thread(
            target=start_dd_honeypot,
            args=[tmpdir],
            daemon=True,
        )
        t.start()
        sleep(2)
        try:
            yield port
        finally:
            monkeypatch.setenv("STOP_HONEYPOT", "true")
            t.join(timeout=5)
