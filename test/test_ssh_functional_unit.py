import json
import os
import time
from pathlib import Path

import paramiko
import pytest

from infra.honeypot_wrapper import create_honeypot
from infra.json_to_sqlite import convert_json_to_sqlite


@pytest.fixture
def ssh_honeypot(tmp_path: Path):
    fs_json = tmp_path / "alpine_fs_small.json"
    fs_db = tmp_path / "alpine_fs_small.db"

    # Write fake FS JSON
    fs_data = {
        "/": {
            "type": "dir",
            "content": {
                "bin": {"type": "dir", "content": {}},
                "etc": {"type": "dir", "content": {}},
                "home": {
                    "type": "dir",
                    "content": {"user": {"type": "dir", "content": {}}},
                },
            },
        }
    }
    fs_json.write_text(json.dumps(fs_data))

    base_dir = os.path.dirname(os.path.dirname(__file__))
    json_to_sqlite_script = os.path.join(base_dir, "src/infra/json_to_sqlite.py")

    convert_json_to_sqlite(fs_json, fs_db)

    data_file = tmp_path / "data.jsonl"
    data_file.touch()

    config = {
        "type": "ssh",
        "port": 0,
        "data_file": str(data_file),
        "system_prompt": "You are a Linux emulator",
        "model_id": "test-model",
        "fs_file": str(fs_db),  # use the converted DB here
    }

    honeypot = create_honeypot(config)
    honeypot.start()
    time.sleep(0.2)
    yield honeypot
    honeypot.stop()


def test_ls_root_directory(ssh_honeypot):
    """Test if ls / returns fake file system root directories"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "localhost", port=ssh_honeypot.port, username="user", password="pass"
    )

    stdin, stdout, stderr = client.exec_command("ls /")
    output = stdout.read().decode().strip()
    client.close()

    assert "bin" in output
    assert "etc" in output
    assert "home" in output
