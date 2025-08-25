import os
import time
from pathlib import Path

import paramiko
import pytest

from infra.honeypot_wrapper import create_honeypot
from ssh_honeypot import SSH_SESSIONS
from infra.interfaces import HoneypotAction


class DummyAction(HoneypotAction):
    def connect(self, auth_info):
        return {"id": "mock-session-id"}

    def query(self, command, session):
        return {"output": "bin\netc\nhome\n"}


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

    action = DummyAction()
    patched = False
    for session in SSH_SESSIONS.values():
        handler = session.get("handler")
        if handler and not isinstance(handler.action, DummyAction):
            handler.action = action
            patched = True
    if patched:
        print("Manually patched session handler(s)")

    stdin, stdout, stderr = client.exec_command("ls /")
    output = stdout.read().decode().strip()
    client.close()

    assert "bin" in output
    assert "etc" in output
    assert "home" in output
