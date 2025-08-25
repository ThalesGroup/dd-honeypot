import logging
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List
from unittest.mock import patch

import paramiko
import pytest
from scp import SCPClient

from infra.honeypot_wrapper import create_honeypot
from ssh_honeypot import SSH_SESSIONS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DummyAction1:
    def connect(self, auth_info):
        return {}  # stub session

    def query(self, command, session):
        return {"output": "Mocked LLM response"}


class DummyAction2:
    def connect(self, auth_info):
        return {}

    def query(self, command, session):
        c = command.strip()
        if c == "ls" or c.startswith("ls "):
            return {"output": "bin\netc\nhome\n"}
        return {"output": "mocked stdout\n"}


@pytest.fixture
def ssh_honeypot():
    SSH_SESSIONS.clear()
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        data_file = temp_path / "data.jsonl"
        key_file = temp_path / "host.key"

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

        action = DummyAction1()

        with patch("infra.data_handler.invoke_llm", return_value="Mocked LLM response"):
            honeypot = create_honeypot(config)
            for session in SSH_SESSIONS.values():
                handler = session.get("handler")
                if handler:
                    handler.action = action
            honeypot.action = action

            def patch_all_handlers():
                while getattr(
                    honeypot, "running", True
                ):  # For PyCharm warning, checks attribute safely
                    for session in SSH_SESSIONS.values():
                        handler = session.get("handler")
                        if handler and handler.action is not action:
                            handler.action = action
                    time.sleep(0.005)

            threading.Thread(target=patch_all_handlers, daemon=True).start()

            honeypot.start()
            time.sleep(1)

            yield honeypot
            honeypot.stop()
        del os.environ["HONEYPOT_HOST_KEY"]  # Cleanup


def manual_patch_sessions(dummy_class, action_instance):
    """Manually patch all current session handlers to the dummy action."""
    patched = False
    for session in SSH_SESSIONS.values():
        handler = session.get("handler")
        if handler and not isinstance(handler.action, dummy_class):
            handler.action = action_instance
            patched = True
    if patched:
        logger.info("Manually patched session handler(s)")
    return patched


def test_basic_command_execution(ssh_honeypot):
    """Test basic exec_command using the SSH honeypot."""
    action = DummyAction1()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "localhost", port=ssh_honeypot.port, username="test", password="test"
    )

    manual_patch_sessions(DummyAction1, action)

    channel = client.get_transport().open_session()
    print(f"Handler action type: {type(ssh_honeypot.action)}")
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
    action = DummyAction1()
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

    manual_patch_sessions(DummyAction1, action)

    channel = client.invoke_shell()
    channel.settimeout(5)

    # Wait for welcome prompt
    output = b""
    start = time.time()
    while time.time() - start < 5 and b"Welcome" not in output:
        if channel.recv_ready():
            output += channel.recv(1024)

    assert b"$user@alpine:$/$ " in output

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

    assert any(
        "Accept error:" in record.getMessage()
        or "Authentication:" in record.getMessage()
        for record in caplog.records
    )


def test_concurrent_connections(ssh_honeypot):
    """Test that multiple SSH clients can connect and respond simultaneously."""
    clients: List[paramiko.SSHClient] = []
    action = DummyAction1()

    def connect_and_run(user: str, cmd: str) -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "localhost", port=ssh_honeypot.port, username=user, password="pass"
        )

        manual_patch_sessions(DummyAction1, action)

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

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(connect_and_run, "user1", "whoami"),
            executor.submit(connect_and_run, "user2", "ls"),
        ]
        results = [future.result() for future in as_completed(futures)]

    out1, out2 = results

    assert "Mocked LLM response" in out1
    assert "Mocked LLM response" in out2


@pytest.fixture
def ssh_honeypot_with_fakefs(tmp_path: Path):
    SSH_SESSIONS.clear()

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

    action = DummyAction2()

    with patch(
        "infra.data_handler.invoke_llm", return_value="Mocked LLM response"
    ):  # Added as safeguard
        honeypot = create_honeypot(config)
        for session in SSH_SESSIONS.values():
            handler = session.get("handler")
            if handler:
                handler.action = action
        honeypot.action = action

    def patch_all_handlers():
        while getattr(honeypot, "running", True):
            for session in SSH_SESSIONS.values():
                handler = session.get("handler")
                if handler and handler.action is not action:
                    handler.action = action
            time.sleep(0.005)

    threading.Thread(target=patch_all_handlers, daemon=True).start()
    honeypot.start()
    time.sleep(1)
    yield honeypot
    honeypot.stop()


def test_ssh_ls_with_fake_fs(ssh_honeypot_with_fakefs):
    action = DummyAction2()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "localhost",
        port=ssh_honeypot_with_fakefs.port,
        username="user",
        password="pass",
    )

    manual_patch_sessions(DummyAction2, action)

    _, stdout, _ = client.exec_command("ls /")
    output = stdout.read().decode().strip()
    client.close()

    assert "bin" in output
    assert "etc" in output


@pytest.mark.skip(reason="skipping for now")
def test_scp_upload(ssh_honeypot_with_fakefs):
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
    test_file = temp_path / "test_scp.txt"
    test_file.write_text("This is a test")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "localhost",
        port=ssh_honeypot_with_fakefs.port,
        username="test",
        password="test",
    )

    with SCPClient(client.get_transport(), sanitize=lambda x: x) as scp:
        scp.put(str(test_file), "/test_uploaded.txt")

    client.close()
