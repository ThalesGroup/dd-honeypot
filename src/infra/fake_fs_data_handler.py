import json
import logging
import tempfile
from pathlib import Path

from infra.fake_fs.commands import handle_ls, handle_cd, handle_mkdir, handle_download
from infra.fake_fs.filesystem import FakeFileSystem
from infra.fake_fs.fs_utils import create_db_from_jsonl_gz
from infra.fake_fs_datastore import FakeFSDataStore
from infra.interfaces import HoneypotSession, HoneypotAction


class FakeFSDataHandler(HoneypotAction):
    def __init__(self, data_file: str, fs_file: str):
        self._data_file = Path(data_file)

        # Load fake filesystem from fs_file
        fs_path = Path(fs_file)

        if fs_path.suffix == ".gz" and fs_path.name.endswith(".jsonl.gz"):
            tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            create_db_from_jsonl_gz(fs_path, tmp_db.name)
            fs_path = Path(tmp_db.name)
        else:
            raise ValueError(
                "Unsupported fakefs file format. Only .jsonl.gz is supported."
            )

        if not fs_path.exists():
            raise FileNotFoundError(f"Missing or failed to generate fs DB: {fs_file}")

        store = FakeFSDataStore(str(fs_path))
        self.fakefs = FakeFileSystem(store)

    def connect(self, auth_info: dict) -> HoneypotSession:
        logging.info(f"FakeFSDataHandler.connect: {auth_info}")
        return HoneypotSession({"cwd": "/", "fs": self.fakefs})

    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        logging.info(f"FakeFSDataHandler.query: {query}")
        query = query.strip()

        if "fs" in session:
            if query.startswith("ls"):
                parts = query.strip().split()
                flags = [p for p in parts if p.startswith("-")]
                return handle_ls(session, flags=" ".join(flags))

            elif query.startswith("cd "):
                parts = query.split(maxsplit=1)
                if len(parts) == 2:
                    return handle_cd(session, parts[1])
                return "Usage: cd <dir>"
            elif query.startswith("mkdir "):
                parts = query.split(maxsplit=1)
                if len(parts) == 2:
                    return handle_mkdir(session, parts[1])
                return "Usage: mkdir <dir>"
            elif "wget" in query.lower() or "curl" in query.lower():
                parts = query.strip().split()
                if len(parts) >= 2:
                    url = parts[-1]
                    logging.info(f"[FakeFSDataHandler] Handling download: {url}")
                    return handle_download(session, url)
                logging.warning("[FakeFSDataHandler] Invalid wget/curl syntax")
                return "Usage: wget <url> or curl <url>"
        return self.query_from_file(query)

    def query_from_file(self, input_str: str) -> str:
        try:
            with self._data_file.open("r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if entry.get("input") == input_str:
                            return entry.get("response", "")
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            logging.warning(f"Data file not found: {self._data_file}")
        return None
