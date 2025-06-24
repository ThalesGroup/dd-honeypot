import os
from typing import Dict, List, Optional

from infra.fake_fs_datastore import FakeFSDataStore


class FileSystemNode:
    def __init__(self, name: str, is_dir: bool = True):
        self.name = name
        self.is_dir = is_dir
        self.children: Dict[str, FileSystemNode] = {}

    def add_child(self, child: "FileSystemNode"):
        if not self.is_dir:
            raise ValueError("Cannot add child to a file")
        self.children[child.name] = child

    def get_child(self, name: str) -> Optional["FileSystemNode"]:
        return self.children.get(name)

    def list_children(self) -> List[str]:
        return sorted(self.children.keys())


class FakeFileSystem:
    def __init__(self, store: FakeFSDataStore):
        self.store = store

    def resolve_path(
        self, path: str, cwd: str = "/", expect_dir=False
    ) -> Optional[dict]:
        norm_path = os.path.normpath(os.path.join(cwd, path))
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        node = self.store.get_node(norm_path)
        if expect_dir and node and not node["is_dir"]:
            return None
        return node

    def create_file(self, path: str, content=""):
        self.store.write_file(path, content)

    def mkdir(self, path: str):
        self.store.mkdir(path)

    def list_children(self, path: str):
        return self.store.list_dir(path)
