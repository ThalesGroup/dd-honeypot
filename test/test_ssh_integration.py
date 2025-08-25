import os
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import paramiko
import pytest
import requests

from infra.honeypot_wrapper import create_honeypot
from infra.interfaces import HoneypotAction
from ssh_honeypot import SSH_SESSIONS


class DummyAction(HoneypotAction):
    def connect(self, auth_info):
        return {}

    def query(self, command, session):
        parts = command.split()
        if parts and parts[0] == "wget":
            url = parts[-1]
            filename = url.split("/")[-1] or "downloaded_file"
            download_dir = os.environ.get("HONEYPOT_DOWNLOAD_DIR", "/tmp")
            file_path = os.path.join(download_dir, filename)

            try:
                response = requests.get(url, stream=True)
                response.raise_for_status()
                with open(file_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                return {"output": f"Downloaded {filename} to {file_path}\n"}
            except Exception as e:
                return {"output": f"Download failed: {str(e)}\n"}

        return {"output": "Mocked command response"}


@pytest.fixture
def ssh_honeypot_with_fs_download():
    SSH_SESSIONS.clear()
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        data_file = temp_path / "data.jsonl"
        key_file = temp_path / "host.key"

        os.environ["HONEYPOT_HOST_KEY"] = str(key_file)
        os.environ["HONEYPOT_DOWNLOAD_DIR"] = temp_dir

        config = {
            "type": "ssh",
            "port": 0,
            "data_file": str(data_file),
            "system_prompt": "You are a Linux terminal emulator.",
            "model_id": "test-model",
        }

        action = DummyAction()

        with patch("infra.data_handler.invoke_llm", return_value="Mocked Response"):
            honeypot = create_honeypot(config)
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

    del os.environ["HONEYPOT_HOST_KEY"]
    del os.environ["HONEYPOT_DOWNLOAD_DIR"]


def manual_patch_sessions(dummy_class, action_instance):
    """Manually patch all current session handlers to the dummy action."""
    patched = False
    for session in SSH_SESSIONS.values():
        handler = session.get("handler")
        if handler and not isinstance(handler.action, dummy_class):
            handler.action = action_instance
            patched = True
    if patched:
        print("Manually patched session handler(s)")
    return patched


@pytest.mark.freeze_time("2025-06-19 14:57:39")
def test_ssh_download_wget(ssh_honeypot_with_fs_download):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "localhost",
        port=ssh_honeypot_with_fs_download.port,
        username="user",
        password="pass",
    )

    action = DummyAction()
    manual_patch_sessions(DummyAction, action)

    _, stdout, _ = client.exec_command(
        "wget https://raw.githubusercontent.com/vinta/awesome-python/master/README.md"
    )

    output = b""
    start = time.time()
    while time.time() - start < 10:
        if stdout.channel.recv_ready():
            output += stdout.channel.recv(1024)
        if stdout.channel.exit_status_ready():
            break
        time.sleep(0.1)

    decoded = output.decode()
    assert "Downloaded README.md" in decoded

    expected_path = os.path.join(os.environ["HONEYPOT_DOWNLOAD_DIR"], "README.md")
    assert os.path.exists(expected_path)
    assert os.path.getsize(expected_path) > 0

    client.close()
