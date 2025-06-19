import os
import tempfile

import freezegun
import paramiko
import pytest
from pathlib import Path

from freezegun import freeze_time

from infra.honeypot_wrapper import create_honeypot


@pytest.fixture
def ssh_honeypot_with_fs_download(tmp_path: Path):
    fs_file = tmp_path / "fs.json"
    fs_file.write_text('{"\\/": {"type": "dir", "content": {}}}')

    data_file = tmp_path / "data.jsonl"

    config = {
        "type": "ssh",
        "port": 0,
        "data_file": str(data_file),
        "system_prompt": "Fake Terminal",
        "model_id": "test-model",
        "fs_file": str(fs_file),
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
            "Length: 78506 [text/plain]\r\n"
            "Saving to: ‘README.md’\r\n"
            "\n"
            "README.md              100%[78506/78506]   1.21K/s   in 0.01s\r\n"
            "\n"
            "2025-06-19 14:57:39 (1.21 KB/s) - ‘README.md’ saved [78506/78506]\n"
        ) in output

        expected_path = os.path.join(tmpdir, "README.md")
        assert os.path.exists(expected_path)
        client.close()
