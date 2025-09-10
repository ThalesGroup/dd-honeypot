import contextlib
import gzip
import json
import os
import tempfile
import threading
from time import sleep
from typing import Generator, List

from honeypot_main_utils import start_dd_honeypot
from honeypot_utils import allocate_port


def get_honeypots_folder() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypots")


def get_honeypot_folder(name: str) -> str:
    return os.path.join(get_honeypots_folder(), name)


def get_config(name: str) -> dict:
    conf_file = os.path.join(get_honeypots_folder(), name, f"config.json")
    return json.load(open(conf_file))


@contextlib.contextmanager
def get_honeypot_main(
    monkeypatch,
    honeypot_configs: List[dict],
    data_jsonl: List[dict] = None,
    fake_fs_jsonl: List[dict] = None,
) -> Generator[int, None, None]:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("STOP_HONEYPOT", "false")
    port = allocate_port()
    for honeypot_config in honeypot_configs:
        honeypot_config["port"] = port
        if "name" not in honeypot_config:
            honeypot_config["name"] = f"test-main-{honeypot_config['type']}-honeypot"
        if "model_id" not in honeypot_config:
            honeypot_config["model_id"] = "test-model-id"
        if "system_prompt" not in honeypot_config:
            honeypot_config["system_prompt"] = ["You are a test honeypot"]
    with tempfile.TemporaryDirectory() as tmpdir:
        for honeypot_config in honeypot_configs:
            honeypot_dir = os.path.join(tmpdir, honeypot_config["name"])
            os.makedirs(honeypot_dir, exist_ok=True)
            json.dump(
                honeypot_config,
                open(os.path.join(honeypot_dir, "config.json"), "w"),
            )
            if "data_file" in honeypot_config and data_jsonl is not None:
                data_file = os.path.join(honeypot_dir, honeypot_config["data_file"])
                with open(data_file, "w") as f:
                    for item in data_jsonl:
                        f.write(json.dumps(item) + "\n")
            if "fs_file" in honeypot_config and fake_fs_jsonl is not None:
                data_file = os.path.join(honeypot_dir, honeypot_config["fs_file"])
                with gzip.open(data_file, "wt") as f:
                    for item in fake_fs_jsonl:
                        f.write(json.dumps(item) + "\n")
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
