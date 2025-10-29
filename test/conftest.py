import contextlib
import gzip
import json
import logging
import os
import socket
import tempfile
import threading
from typing import Generator, List

from honeypot_main_utils import start_dd_honeypot


def _free_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def get_honeypots_folder() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypots")


def get_honeypot_folder(name: str) -> str:
    return os.path.join(get_honeypots_folder(), name)


def get_config(name: str) -> dict:
    conf_file = os.path.join(get_honeypots_folder(), name, f"config.json")
    return json.load(open(conf_file))


def _wait_http(port, retries=30, delay=0.1):
    import requests, time

    for _ in range(retries):
        try:
            requests.get(f"http://127.0.0.1:{port}", timeout=0.25)
            return
        except OSError:
            time.sleep(delay)


@contextlib.contextmanager
def get_honeypot_main(
    monkeypatch,
    honeypot_configs: List[dict],
    data_jsonl: List[dict] = None,
    fake_fs_jsonl: List[dict] = None,
) -> Generator[int, None, None]:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("STOP_HONEYPOT", "false")
    # port = allocate_port()
    dispatcher_port = None
    for cfg in honeypot_configs:
        if cfg.get("is_dispatcher"):
            dispatcher_port = _free_port()
            cfg["port"] = dispatcher_port
        else:
            cfg["port"] = cfg.get("port", 0)
    for honeypot_config in honeypot_configs:
        # honeypot_config["port"] = port
        if "name" not in honeypot_config:
            honeypot_config["name"] = f"test-main-{honeypot_config['type']}-honeypot"
        if "model_id" not in honeypot_config:
            honeypot_config["model_id"] = "test-model-id"
        if "system_prompt" not in honeypot_config:
            honeypot_config["system_prompt"] = ["You are a test honeypot"]
    with tempfile.TemporaryDirectory() as tmpdir:
        hp_dirs = []
        for honeypot_config in honeypot_configs:
            honeypot_dir = os.path.join(tmpdir, honeypot_config["name"])
            os.makedirs(honeypot_dir, exist_ok=True)
            json.dump(
                honeypot_config, open(os.path.join(honeypot_dir, "config.json"), "w")
            )
            if honeypot_config.get("is_dispatcher") and data_jsonl:
                data_file = os.path.join(honeypot_dir, "dispatcher_data.jsonl")
                with open(data_file, "w") as f:
                    for item in data_jsonl:
                        f.write(json.dumps(item) + "\n")
            if "data_file" in honeypot_config and data_jsonl is not None:
                data_file = os.path.join(honeypot_dir, honeypot_config["data_file"])
                with open(data_file, "w") as f:
                    for item in data_jsonl:
                        f.write(json.dumps(item) + "\n")
            if "fs_file" in honeypot_config and fake_fs_jsonl is not None:
                fs_path = os.path.join(honeypot_dir, honeypot_config["fs_file"])
                with gzip.open(fs_path, "wt") as f:
                    for item in fake_fs_jsonl:
                        f.write(json.dumps(item) + "\n")

            hp_dirs.append(honeypot_dir)

        t = threading.Thread(target=start_dd_honeypot, args=[tmpdir], daemon=True)
        t.start()

        try:
            if any(c.get("is_dispatcher") for c in honeypot_configs):
                _wait_http(dispatcher_port)
                yield dispatcher_port
            else:
                # legacy single honeypot: read bound_port written by the listener
                assert hp_dirs, "no honeypot folder created"
                hp_dir = hp_dirs[0]
                bound_file = os.path.join(hp_dir, "bound_port")

                import time, socket

                deadline = time.time() + 10
                while not os.path.exists(bound_file) and time.time() < deadline:
                    time.sleep(0.05)
                if not os.path.exists(bound_file):
                    try:
                        logging.error("Files in %s: %s", hp_dir, os.listdir(hp_dir))
                    except OSError:
                        pass
                    raise RuntimeError("honeypot did not write bound_port")

                port = int(open(bound_file).read().strip())

                for _ in range(30):
                    try:
                        s = socket.socket()
                        s.settimeout(0.25)
                        s.connect(("127.0.0.1", port))
                        s.close()
                        break
                    except OSError:
                        time.sleep(0.1)

                yield port
        finally:
            monkeypatch.setenv("STOP_HONEYPOT", "true")
            t.join(timeout=5)
