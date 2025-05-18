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

    assert "/" in handle_ls(session)