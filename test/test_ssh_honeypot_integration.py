import logging
import time
from socket import socket

import paramiko
import pytest

from conftest import get_honeypot_main
from honeypot_utils import init_env_from_file


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
        honeypot_configs=[_HONEYPOT_CONFIG],
        data_jsonl=[{"command": "test_static_command", "response": "test_response"}],
        fake_fs_jsonl=_FS_DATA,
    ) as port:
        logging.info("port: %s", port)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect("localhost", port=port, username="test", password="test")

        shell = client.invoke_shell()
        shell.settimeout(60)

        # Helper function to send command and read response
        def send_command_and_read(command, timeout=30):
            shell.send(command + "\n")
            time.sleep(0.5)

            output = ""
            start_time = time.time()

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    data = shell.recv(1024).decode()
                    output += data
                    # Look for command prompt to know when output is complete
                    if "$" in data or "#" in data:
                        break
                else:
                    time.sleep(0.1)

            return output.strip()

        time.sleep(1)
        shell.recv(1024).decode() if shell.recv_ready() else ""

        output1 = send_command_and_read("test_static_command")
        assert "test_response" in output1

        output2 = send_command_and_read("ls /")
        assert "root" in output2

        output3 = send_command_and_read("whoami", timeout=60)
        assert "root" in output3

        shell.close()
        client.close()
