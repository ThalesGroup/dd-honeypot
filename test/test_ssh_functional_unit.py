import json
import time
import pytest
import paramiko
from pathlib import Path
from infra.honeypot_wrapper import create_honeypot


@pytest.fixture
def ssh_honeypot(tmp_path: Path):
    """Start honeypot on random port with fake_fs"""
    # Write minimal fake file system to file
    fs_file = tmp_path / "alpine_fs_small.json"
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
    with open(fs_file, "w") as f:
        json.dump(fs_data, f)

    # Dummy data file
    data_file = tmp_path / "data.jsonl"
    data_file.touch()

    config = {
        "type": "ssh",
        "port": 0,
        "data_file": str(data_file),
        "system_prompt": "You are a Linux emulator",
        "model_id": "test-model",
        "fs_file": str(fs_file),
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
