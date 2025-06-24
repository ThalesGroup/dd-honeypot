import os
import shutil
import tempfile

import pytest

from infra.fake_fs.commands import handle_ls, handle_cd, handle_mkdir, handle_download
from infra.fake_fs_data_handler import FakeFSDataHandler
from infra.json_to_sqlite import convert_json_to_sqlite


@pytest.mark.parametrize(
    "fs_path",
    [
        "test/honeypots/alpine/fs_alpine.db",
        "test/honeypots/busybox/fs_busybox.db",
        "test/honeypots/dlink_telnet/alpine_fs_small.db",
    ],
)
def test_basic_ls_and_cd(fs_path):
    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        system_prompt="You are a terminal",
        model_id="test-model",
        fs_file=fs_path,
    )
    session = handler.connect({})

    output = handler.query("ls", session)
    assert isinstance(output, str)
    print("LS / output:", output)
    assert "bin" in output
    assert "etc" in output
    assert "home" in output

    handle_cd(session, "home")
    assert session["cwd"] == "/home"
    assert "" in handle_ls(session)


def test_basic_ls_from_root():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    db_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.db")

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        system_prompt="irrelevant",
        model_id="irrelevant",
        fs_file=db_path,
    )

    session = handler.connect({})
    result = handle_ls(session)

    print("LS result:", result)

    assert "bin" in result
    assert "etc" in result
    assert "home" in result


def test_mkdir_creates_directory(tmp_path):
    base_dir = os.path.dirname(os.path.dirname(__file__))
    orig_db = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.db")
    tmp_db = tmp_path / "fs.db"
    shutil.copy(orig_db, tmp_db)

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        system_prompt="irrelevant",
        model_id="irrelevant",
        fs_file=str(tmp_db),
    )

    session = handler.connect({})
    output = handle_mkdir(session, "newdir_temp")

    assert output == ""
    children = session["fs"].store.list_dir(session["cwd"])
    names = [child["name"] for child in children]
    assert "newdir_temp" in names


def test_ls_long_format(tmp_path):
    base_dir = os.path.dirname(os.path.dirname(__file__))
    orig_db = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.db")
    tmp_db = tmp_path / "fs.db"
    shutil.copy(orig_db, tmp_db)

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        system_prompt="irrelevant",
        model_id="irrelevant",
        fs_file=str(tmp_db),
    )

    session = handler.connect({})
    result = handle_ls(session, flags="-l")
    assert "bin" in result


def test_handle_wget_creates_file(tmp_path, monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("HONEYPOT_DOWNLOAD_DIR", tmpdir)

    base_dir = os.path.dirname(os.path.dirname(__file__))
    orig_db = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.db")
    tmp_db = tmp_path / "fs.db"
    shutil.copy(orig_db, tmp_db)

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        system_prompt="irrelevant",
        model_id="irrelevant",
        fs_file=str(tmp_db),
    )

    session = handler.connect({})

    url = "http://test.com/malware.sh"
    output = handle_download(session, url)

    children = session["fs"].store.list_dir(session["cwd"])
    names = [child["name"] for child in children]
    assert "malware.sh" in names

    assert "saved" in output
    assert session["downloads"][0]["url"] == url


def test_fakefs_query_fallback(tmp_path):
    # Create test data
    data_file = tmp_path / "data.jsonl"
    data_file.write_text('{"input": "whoami", "response": "root\\n"}\n')

    fs_file = tmp_path / "fs.json"
    fs_file.write_text(
        r"""{
        "/": {
            "type": "dir",
            "content": {}
        }
    }"""
    )

    fs_db = tmp_path / "fs.db"

    base_dir = os.path.dirname(os.path.dirname(__file__))
    json_to_sqlite_script = os.path.join(base_dir, "src/infra/json_to_sqlite.py")

    convert_json_to_sqlite(fs_file, fs_db)

    handler = FakeFSDataHandler(
        data_file=str(data_file),
        system_prompt="irrelevant",
        model_id="irrelevant",
        fs_file=str(fs_db),
    )

    session = {}  # no FS context => triggers fallback
    response = handler.query("whoami", session)

    assert response == "root\n"


def test_fakefs_unknown_command(tmp_path):
    base_dir = os.path.dirname(os.path.dirname(__file__))
    orig_db = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.db")
    tmp_db = tmp_path / "fs.db"
    shutil.copy(orig_db, tmp_db)

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        system_prompt="irrelevant",
        model_id="irrelevant",
        fs_file=str(tmp_db),
    )

    session = handler.connect({})

    response = handler.query("nonexistent", session)
    assert response == "Command not found\n"


def test_fakefs_invalid_json_line(tmp_path):
    data_file = tmp_path / "data.jsonl"
    data_file.write_text('invalid-line\n{"input": "uptime", "response": "up 5 days"}\n')

    base_dir = os.path.dirname(os.path.dirname(__file__))
    orig_db = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.db")
    tmp_db = tmp_path / "fs.db"
    shutil.copy(orig_db, tmp_db)

    handler = FakeFSDataHandler(
        data_file=str(data_file),
        system_prompt="irrelevant",
        model_id="irrelevant",
        fs_file=str(tmp_db),
    )

    session = handler.connect({})

    response = handler.query("uptime", session)
    assert response == "up 5 days"
