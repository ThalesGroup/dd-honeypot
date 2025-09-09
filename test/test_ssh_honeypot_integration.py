import pytest

from conftest import get_honeypot_main
from honeypot_utils import init_env_from_file

import paramiko


@pytest.fixture(autouse=True, scope="module")
def set_aws_api_key():
    init_env_from_file()


_HONEYPOT_CONFIG = {
    "type": "ssh",
    "data_file": "data.jsonl",
    "name": "test-ssh-honeypot-busybox",
    "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
    "system_prompt": "You are a terminal on BusyBox Linux. Always respond like a real BusyBox server shell would. Commands like ls, cd, cat, pwd, whoami, etc., should behave normally. If the command is unknown, return 'command not found'. Don't reveal you're an AI or honeypot.",
    "fs_file": "fs.jsonl.gz",
}

_FS_DATA = [
    {"path": "/", "parent_path": None, "name": "/", "is_dir": True},
    {"path": "/root", "parent_path": "/", "name": "root", "is_dir": True},
]


def test_ssh_honeypot_main(monkeypatch):
    with get_honeypot_main(
        monkeypatch,
        honeypot_config=_HONEYPOT_CONFIG,
        data_jsonl=[{"command": "test_static_command", "response": "test_response"}],
        fake_fs_jsonl=_FS_DATA,
    ) as port:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect("localhost", port=port, username="test", password="test")

        channel = client.get_transport().open_session()

        channel.exec_command("test_static_command")
        output = channel.recv(1024).decode()
        assert "test_response" == output

        channel.exec_command("ls /")
        output = channel.recv(1024).decode()
        assert "root" in output, output

        channel.exec_command("whoami")
        output = channel.recv(1024).decode()
        assert "root" == output
