import os
import time
from pathlib import Path
from unittest.mock import Mock

import paramiko
import pytest

from infra.honeypot_wrapper import create_honeypot


@pytest.fixture
def ssh_honeypot(tmp_path: Path):

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
    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    data_file = tmp_path / "data.jsonl"
    data_file.touch()

    config = {
        "type": "ssh",
        "port": 0,
        "data_file": str(data_file),
        "system_prompt": "You are a Linux emulator",
        "model_id": "test-model",
        "fs_file": fs_path,
    }

    mock_action = Mock()
    mock_action.query.return_value = "bin\netc\nhome"
    mock_action.connect.return_value = {}

    honeypot = create_honeypot(config)
    honeypot.action = mock_action
    honeypot.start()
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
