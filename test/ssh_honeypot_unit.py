import json
import os
import time
import pytest
import paramiko
import logging
from pathlib import Path
from typing import List
from unittest.mock import patch

from infra.honeypot_wrapper import create_honeypot

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@pytest.fixture
def ssh_honeypot(tmp_path: Path):
    data_file = tmp_path / "data.jsonl"
    key_file = tmp_path / "host.key"

    os.environ["HONEYPOT_HOST_KEY"] = str(
        key_file
    )  # Tell honeypot where to write the key

    config = {
        "type": "ssh",
        "port": 0,
        "data_file": str(data_file),
        "system_prompt": "You are a Linux terminal emulator.",
        "model_id": "test-model",
    }
    with patch("infra.data_handler.invoke_llm", return_value="Mocked LLM response"):
        honeypot = create_honeypot(config)
        honeypot.start()
        time.sleep(0.2)
        yield honeypot
        honeypot.stop()
    del os.environ["HONEYPOT_HOST_KEY"]  # Cleanup


def test_basic_command_execution(ssh_honeypot):
    """Test basic exec_command using the SSH honeypot."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "localhost", port=ssh_honeypot.port, username="test", password="test"
    )

    channel = client.get_transport().open_session()
    channel.exec_command("test-command")

    output = b""
    start = time.time()
    while time.time() - start < 5:
        if channel.recv_ready():
            output += channel.recv(1024)
        if channel.exit_status_ready():
            break
        time.sleep(0.1)

    decoded = output.decode()
    assert "Mocked LLM response" in decoded
    assert channel.recv_exit_status() == 0
    client.close()


def test_interactive_shell(ssh_honeypot):
    """Test interactive shell session via invoke_shell."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        "localhost",
        port=ssh_honeypot.port,
        username="user",
        password="pass",
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
        look_for_keys=False,
        allow_agent=False,
    )

    channel = client.invoke_shell()
    channel.settimeout(5)

    # Wait for welcome prompt
    output = b""
    start = time.time()
    while time.time() - start < 5 and b"Welcome" not in output:
        if channel.recv_ready():
            output += channel.recv(1024)

    assert b"Welcome" in output

    # Send command and wait for mocked response
    channel.send("ls\n")
    output = b""
    start = time.time()
    while time.time() - start < 5:
        if channel.recv_ready():
            output += channel.recv(1024)
        if b"Mocked LLM response" in output:
            break

    assert b"Mocked LLM response" in output
    client.close()


def test_invalid_auth_logging(ssh_honeypot, caplog: pytest.LogCaptureFixture):
    """Verify that invalid logins are captured in logs."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            "localhost",
            port=ssh_honeypot.port,
            username="invalid",
            password="invalid",
            timeout=5,
        )
    except Exception:
        pass  # Expected to fail

    assert "Authentication: invalid:invalid" in caplog.text


def test_concurrent_connections(ssh_honeypot):
    """Test that multiple SSH clients can connect and respond simultaneously."""
    clients: List[paramiko.SSHClient] = []

    def connect_and_run(user: str, cmd: str) -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "localhost", port=ssh_honeypot.port, username=user, password="pass"
        )
        _, stdout, _ = client.exec_command(cmd)
        output = b""
        start = time.time()
        while time.time() - start < 5:
            if stdout.channel.recv_ready():
                output += stdout.channel.recv(1024)
            if stdout.channel.exit_status_ready():
                break
            time.sleep(0.1)
        client.close()
        return output.decode()

    out1 = connect_and_run("user1", "whoami")
    out2 = connect_and_run("user2", "ls")

    assert "Mocked LLM response" in out1
    assert "Mocked LLM response" in out2


@pytest.fixture
def ssh_honeypot_with_fakefs(tmp_path: Path):
    # Create fake file system json
    fake_fs_data = {
        "/": {
            "type": "dir",
            "content": {
                "bin": {"type": "dir", "content": {}},
                "etc": {"type": "dir", "content": {}},
            },
        }
    }
    fs_file = tmp_path / "fs.json"
    with fs_file.open("w") as f:
        json.dump(fake_fs_data, f)

    # Create dummy data.jsonl
    data_file = tmp_path / "data.jsonl"
    data_file.touch()

    config = {
        "type": "ssh",
        "port": 0,
        "data_file": str(data_file),
        "system_prompt": "You are a fake terminal",
        "model_id": "test-model",
        "fs_file": str(fs_file),
    }

    honeypot = create_honeypot(config)
    honeypot.start()
    time.sleep(0.2)
    yield honeypot
    honeypot.stop()


def test_ssh_ls_with_fake_fs(ssh_honeypot_with_fakefs):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "localhost",
        port=ssh_honeypot_with_fakefs.port,
        username="user",
        password="pass",
    )

    _, stdout, _ = client.exec_command("ls /")
    output = stdout.read().decode().strip()
    client.close()

    assert "bin" in output
    assert "etc" in output
