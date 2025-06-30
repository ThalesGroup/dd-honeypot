import json
import os
from pathlib import Path

import sqlite_utils

from infra.fake_fs.filesystem import FileSystemNode, FakeFileSystem
from infra.fake_fs.commands import handle_download

import tempfile

from infra.fake_fs_datastore import FakeFSDataStore
from infra.json_to_sqlite import convert_json_to_sqlite


def test_real_wget_download(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("HONEYPOT_DOWNLOAD_DIR", tmpdir)

        base_dir = os.path.dirname(os.path.dirname(__file__))
        fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

        store = FakeFSDataStore(fs_path)
        fs = FakeFileSystem(store)

        session = {
            "cwd": "/",
            "fs": fs,
        }

        url = "https://raw.githubusercontent.com/vinta/awesome-python/master/README.md"
        output = handle_download(session, url)

        entries = store.list_dir("/")
        assert any(e["name"] == "README.md" for e in entries)


def test_real_curl_download(monkeypatch):

    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("HONEYPOT_DOWNLOAD_DIR", tmpdir)

        base_dir = os.path.dirname(os.path.dirname(__file__))
        fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

        store = FakeFSDataStore(fs_path)
        fs = FakeFileSystem(store)

        session = {
            "cwd": "/",
            "fs": fs,
        }

        url = "https://raw.githubusercontent.com/vinta/awesome-python/master/README.md"
        command = f"curl -O {url}"
        output = handle_download(session, command)

        entries = store.list_dir("/")
        assert any(e["name"] == "README.md" for e in entries)
