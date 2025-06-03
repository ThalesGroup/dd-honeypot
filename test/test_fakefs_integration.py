import os
from infra.fake_fs.filesystem import FileSystemNode, FakeFileSystem
from infra.fake_fs.commands import handle_download

import tempfile


def test_real_wget_download(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("HONEYPOT_DOWNLOAD_DIR", tmpdir)

        session = {
            "cwd": "/",
            "fs": FakeFileSystem(FileSystemNode("/")),
        }

        url = "https://raw.githubusercontent.com/vinta/awesome-python/master/README.md"
        output = handle_download(session, url)

        filename = url.strip().split("/")[-1]
        expected_path = os.path.join(tmpdir, filename)

        assert os.path.exists(expected_path), f"{expected_path} not found"
        assert "saved" in output


def test_real_curl_download(monkeypatch):

    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("HONEYPOT_DOWNLOAD_DIR", tmpdir)

        session = {
            "cwd": "/",
            "fs": FakeFileSystem(FileSystemNode("/")),
        }

        url = "https://raw.githubusercontent.com/vinta/awesome-python/master/README.md"
        command = f"curl -O {url}"
        output = handle_download(session, command)

        filename = url.split("/")[-1]
        saved_path = os.path.join(tmpdir, filename)

        assert os.path.exists(saved_path), f"{saved_path} not found"
        assert "saved" in output
