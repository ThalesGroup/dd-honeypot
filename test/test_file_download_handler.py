from unittest.mock import patch

from infra.File_download_handler import FileDownloadHandler


class DummyFakeFS:
    def create_file(self, session, filename, content):
        session.files[filename] = content


class DummySession:
    def __init__(self):
        self.files = {}


@patch("infra.File_download_handler.requests.get")
def test_wget_success(mock_get, tmp_path):
    mock_get.return_value.text = "fake content"
    session = DummySession()
    handler = FileDownloadHandler(fakefs_handler=DummyFakeFS(), download_dir=tmp_path)

    command = "wget http://example.com/fake.txt"
    response = handler.query(command, session)

    assert "Downloaded fake.txt" in response
    assert "fake.txt" in session.files
    assert tmp_path.joinpath("fake.txt").read_text() == "fake content"
