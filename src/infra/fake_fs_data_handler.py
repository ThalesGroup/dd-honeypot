import logging
import json
from pathlib import Path

from infra.data_handler import DataHandler
from infra.fake_fs.filesystem import FakeFileSystem
from infra.fake_fs.commands import handle_ls, handle_cd, handle_mkdir, handle_download
from infra.interfaces import HoneypotSession


class FakeFSDataHandler(DataHandler):
    def __init__(self, data_file: str, system_prompt: str, model_id: str, fs_file: str):
        # super().__init__() if it preloads self.data
        self.data_file = Path(data_file)
        self.system_prompt = system_prompt
        self.model_id = model_id

        # Load fake filesystem from fs_file
        fs_path = Path(fs_file)
        if not fs_path.exists():
            raise FileNotFoundError(f"Missing fake fs file: {fs_file}")
        with fs_path.open() as f:
            fs_data = json.load(f)
        self.fakefs = FakeFileSystem.from_json(fs_data)

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
            with self.data_file.open("r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if entry.get("input") == input_str:
                            return entry.get("response", "")
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            logging.warning(f"Data file not found: {self.data_file}")
        return "Command not found\n"
