import json
import os
from infra.fake_fs.commands import handle_ls, handle_cd, handle_mkdir, handle_wget
from infra.fake_fs.filesystem import FakeFileSystem, FileSystemNode


def test_basic_ls_and_cd():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    json_path = os.path.join(base_dir, "src", "alpine_fs_small.json")

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
    assert session["cwd"] == "//home"
    assert "user" in handle_ls(session)


def test_basic_ls_from_root():

    base_dir = os.path.dirname(os.path.dirname(__file__))
    json_path = os.path.join(base_dir, "src", "alpine_fs_small.json")

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


def test_handle_wget_creates_file():
    fs = FakeFileSystem(FileSystemNode("/"))
    session = {"cwd": "/", "fs": fs}
    url = "http://test.com/malware.sh"
    output = handle_wget(session, url)

    assert "malware.sh" in fs.root.list_children()
    assert "saved" in output
    assert session["downloads"][0]["url"] == url
