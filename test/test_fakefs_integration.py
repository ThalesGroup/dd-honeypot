import os
from infra.fake_fs.filesystem import FileSystemNode, FakeFileSystem
from infra.fake_fs.commands import handle_wget


def test_real_wget_to_downloaded_files_dir():
    fs = FakeFileSystem(FileSystemNode("/"))
    session = {"cwd": "/", "fs": fs}

    url = "https://raw.githubusercontent.com/vinta/awesome-python/master/README.md"
    filename = url.strip().split("/")[-1]

    output = handle_wget(session, url)

    expected_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../downloaded_files")
    )
    expected_path = os.path.join(expected_dir, filename)

    assert os.path.exists(expected_path), f"{expected_path} not found"
    assert os.path.getsize(expected_path) > 0
    assert "saved" in output
    assert session["downloads"][0]["url"] == url
