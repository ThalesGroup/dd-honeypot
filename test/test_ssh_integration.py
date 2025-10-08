import os
import tempfile
from pathlib import Path

import paramiko
import pytest
from freezegun import freeze_time

from infra.honeypot_wrapper import create_honeypot


@pytest.fixture
def ssh_honeypot_with_fs_download(tmp_path: Path):

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
        "fs_file": str(fs_path),  # use the converted DB here
    }

    honeypot = create_honeypot(config)
    honeypot.start()
    yield honeypot
    honeypot.stop()


@freeze_time("2025-06-19 14:57:39")
def test_ssh_download_wget(monkeypatch, ssh_honeypot_with_fs_download):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("HONEYPOT_DOWNLOAD_DIR", tmpdir)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "localhost",
            port=ssh_honeypot_with_fs_download.port,
            username="user",
            password="pass",
        )

        _, stdout, _ = client.exec_command(
            "wget https://raw.githubusercontent.com/vinta/awesome-python/master/README.md"
        )
        output = stdout.read().decode()
        assert (
            "--2025-06-19 14:57:39--  "
            "https://raw.githubusercontent.com/vinta/awesome-python/master/README.md\n"
            "Resolving raw.githubusercontent.com... done.\r\n"
            "Connecting to raw.githubusercontent.com|192.0.2.1|:80... connected.\r\n"
            "HTTP request sent, awaiting response... 200 OK\r\n"
            "Length: 78921 [text/plain]\r\n"
            "Saving to: ‘README.md’\r\n"
            "\n"
            "README.md              100%[78921/78921]   1.21K/s   in 0.01s\r\n"
            "\n"
            "2025-06-19 14:57:39 (1.21 KB/s) - ‘README.md’ saved [78921/78921]"
        ) in output

        expected_path = os.path.join(tmpdir, "README.md")
        assert os.path.exists(expected_path)
        client.close()
