import json
import os
from infra.fake_fs.filesystem import FakeFileSystem
from infra.fake_fs.commands import handle_ls, handle_cd


def test_basic_ls_and_cd():
    base_dir = os.path.dirname(__file__)
    json_path = os.path.join(base_dir, "honeypots/ssh/alpine_fs_small.json")

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
    from infra.fake_fs.filesystem import FakeFileSystem
    from infra.fake_fs.commands import handle_ls
    import json
    import os

    base_dir = os.path.dirname(__file__)
    json_path = os.path.join(base_dir, "honeypots/ssh/alpine_fs_small.json")

    with open(json_path) as f:
        data = json.load(f)

    fs = FakeFileSystem.from_json(data)
    session = {"cwd": "/", "fs": fs}

    result = handle_ls(session)
    print("LS result:", result)

    assert "bin" in result
    assert "etc" in result
    assert "home" in result
