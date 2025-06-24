import json
import os
from infra.fake_fs.filesystem import FileSystemNode, FakeFileSystem
from infra.fake_fs.commands import handle_download

import tempfile

from infra.fake_fs_datastore import FakeFSDataStore
from infra.json_to_sqlite import convert_json_to_sqlite


def test_real_wget_download(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("HONEYPOT_DOWNLOAD_DIR", tmpdir)

        fs_json = os.path.join(tmpdir, "fs.json")
        fs_data = {"/": {"type": "dir", "content": {}}}
        with open(fs_json, "w") as f:
            json.dump(fs_data, f)

        fs_db = os.path.join(tmpdir, "fs.db")
        base_dir = os.path.dirname(os.path.dirname(__file__))
        json_to_sqlite_script = os.path.join(base_dir, "src/infra/json_to_sqlite.py")

        convert_json_to_sqlite(fs_json, fs_db)

        # Step 3: Use real store and FS
        store = FakeFSDataStore(fs_db)
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

        fs_json = os.path.join(tmpdir, "fs.json")
        fs_data = {"/": {"type": "dir", "content": {}}}
        with open(fs_json, "w") as f:
            json.dump(fs_data, f)

        fs_db = os.path.join(tmpdir, "fs.db")
        base_dir = os.path.dirname(os.path.dirname(__file__))
        json_to_sqlite_script = os.path.join(base_dir, "src/infra/json_to_sqlite.py")

        convert_json_to_sqlite(fs_json, fs_db)

        store = FakeFSDataStore(fs_db)
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
