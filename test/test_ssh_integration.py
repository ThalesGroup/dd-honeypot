import os
import tempfile
import paramiko
import pytest
from pathlib import Path
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
        assert "saved" in output

        expected_path = os.path.join(tmpdir, "README.md")
        assert os.path.exists(expected_path)
        client.close()
