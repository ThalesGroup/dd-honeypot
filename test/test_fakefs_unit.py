import json
import os
import tempfile

from infra.fake_fs.commands import handle_ls, handle_cd, handle_mkdir, handle_download
from infra.fake_fs.filesystem import FakeFileSystem, FileSystemNode
from infra.fake_fs_data_handler import FakeFSDataHandler


def test_basic_ls_and_cd():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    json_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.json")

    with open(json_path) as f:
        fs_data = json.load(f)

    fs = FakeFileSystem.from_json(fs_data)
    session = {"cwd": "/", "fs": fs}

    output = handle_ls(session)
    print("LS / output:", output)
    assert "bin" in output
    assert "etc" in output
    assert "home" in output

    handle_cd(session, "home")
    assert session["cwd"] == "/home"
    assert "" in handle_ls(session)


def test_basic_ls_from_root():

    base_dir = os.path.dirname(os.path.dirname(__file__))
    json_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.json")

    with open(json_path) as f:
        data = json.load(f)

    fs = FakeFileSystem.from_json(data)
    session = {"cwd": "/", "fs": fs}

    result = handle_ls(session)
    print("LS result:", result)

    assert "bin" in result
    assert "etc" in result
    assert "home" in result


def test_mkdir_creates_directory():
    fs = FakeFileSystem(FileSystemNode("/"))
    session = {"cwd": "/", "fs": fs}
    output = handle_mkdir(session, "newdir")
    assert output == ""
    assert "newdir" in fs.root.list_children()


def test_ls_long_format():
    fs = FakeFileSystem(FileSystemNode("/"))
    fs.root.add_child(FileSystemNode("bin", is_dir=True))
    fs.root.add_child(FileSystemNode("file.txt", is_dir=False))
    session = {"cwd": "/", "fs": fs}
    result = handle_ls(session, flags="-l")
    assert "bin" in result


def test_handle_wget_creates_file(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("HONEYPOT_DOWNLOAD_DIR", tmpdir)
    fs = FakeFileSystem(FileSystemNode("/"))
    session = {"cwd": "/", "fs": fs}
    url = "http://test.com/malware.sh"
    output = handle_download(session, url)

    assert "malware.sh" in fs.root.list_children()
    assert "saved" in output
    assert session["downloads"][0]["url"] == url


def test_fakefs_query_fallback(tmp_path):
    # Create a minimal fake data.jsonl file
    data_file = tmp_path / "data.jsonl"
    data_file.write_text('{"input": "whoami", "response": "root\\n"}\n')

    # Valid minimal FS with root directory
    fs_file = tmp_path / "fs.json"
    fs_file.write_text(
        r"""{
        "/": {
            "type": "dir",
            "content": {}
        }
    }"""
    )

    handler = FakeFSDataHandler(
        data_file=str(data_file),
        system_prompt="irrelevant",
        model_id="gpt-3.5",
        fs_file=str(fs_file),
    )

    session = {}  # No fs in session => fallback

    response = handler.query("whoami", session)

    assert response == "root\n"


def test_fakefs_unknown_command(tmp_path):
    data_file = tmp_path / "data.jsonl"
    data_file.write_text('{"input": "echo test", "response": "test\\n"}\n')
    fs_file = tmp_path / "fs.json"
    fs_file.write_text(
        r"""{
        "/": {
            "type": "dir",
            "content": {}
        }
    }"""
    )

    handler = FakeFSDataHandler(
        data_file=str(data_file), system_prompt="", model_id="", fs_file=str(fs_file)
    )

    response = handler.query("nonexistent", {})
    assert response == "Command not found\n"


def test_fakefs_invalid_json_line(tmp_path):
    data_file = tmp_path / "data.jsonl"
    data_file.write_text('{"input": "uptime", "response": "up 5 days"}\nINVALID LINE\n')
    fs_file = tmp_path / "fs.json"
    fs_file.write_text(
        r"""{
        "/": {
            "type": "dir",
            "content": {}
        }
    }"""
    )

    handler = FakeFSDataHandler(
        data_file=str(data_file), system_prompt="", model_id="", fs_file=str(fs_file)
    )

    response = handler.query("uptime", {})
    assert response == "up 5 days"
