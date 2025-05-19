from typing import Dict, List, Optional


class FileSystemNode:
    def __init__(self, name: str, is_dir: bool = True):
        self.name = name
        self.is_dir = is_dir
        self.children: Dict[str, FileSystemNode] = {}

    def add_child(self, child: 'FileSystemNode'):
        if not self.is_dir:
            raise ValueError("Cannot add child to a file")
        self.children[child.name] = child

    def get_child(self, name: str) -> Optional['FileSystemNode']:
        return self.children.get(name)

    def list_children(self) -> List[str]:
        return sorted(self.children.keys())


class FakeFileSystem:
    def __init__(self, root: FileSystemNode):
        self.root = root

    @classmethod
    def from_json(cls, json_data: Dict) -> 'FakeFileSystem':
        def build_node(name, data):
            node = FileSystemNode(name, is_dir=True)
            for key, val in data.items():
                if isinstance(val, dict):
                    node.add_child(build_node(key, val))
                else:
                    node.add_child(FileSystemNode(key, is_dir=False))
            return node

        root_node = build_node("/", json_data)
        return cls(root_node)

    def resolve_path(self, path: str, cwd: str = "/") -> Optional[FileSystemNode]:
        parts = (cwd + "/" + path).strip("/").split("/")
        current = self.root
        for part in parts:
            if part in ("", "."):
                continue
            if part == "..":
                # No real parent traversal for now
                continue
            current = current.get_child(part)
            if current is None:
                return None
        return current