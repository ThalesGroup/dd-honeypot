import json

import pytest

from infra.fake_fs.commands import handle_cd
from infra.fake_fs.filesystem import FakeFileSystem


# reuse the FS
@pytest.fixture(scope="module")
def fake_fs():
    with open("honeypots/ssh/alpine_fs_small.json") as f:
        data = json.load(f)
    return FakeFileSystem.from_json(data)


def load_cd_test_cases():
    with open("test_cd_commands.jsonl") as f:
        for line in f:
            yield json.loads(line)


@pytest.mark.parametrize("test_case", load_cd_test_cases())
def test_cd_navigation(fake_fs, test_case):
    session = {"fs": fake_fs, "cwd": test_case["cwd"]}
    output = handle_cd(session, test_case["command"].replace("cd ", ""))

    if "expected_error" in test_case:
        assert output.strip() == test_case["expected_error"]
    else:
        assert output.strip() == test_case["expected_cwd"]
        assert session["cwd"] == test_case["expected_cwd"]
