from typing import Dict, List, Optional


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
    def __init__(self, root: FileSystemNode):
        self.root = root

    @staticmethod
    def from_json(data: dict) -> "FakeFileSystem":
        def build_node(name, node_data):
            is_dir = node_data["type"] == "dir"
            node = FileSystemNode(name, is_dir=is_dir)
            if is_dir:
                for child_name, child_data in node_data.get("content", {}).items():
                    node.add_child(build_node(child_name, child_data))
            return node

        root_data = data["/"]
        root_node = build_node("/", root_data)
        return FakeFileSystem(root_node)

    def resolve_path(
        self,
        path: str,
        cwd: str = "/",
        create_missing: bool = False,
        expect_dir: bool = False,
    ) -> Optional[FileSystemNode]:
        parts = (cwd + "/" + path).strip("/").split("/")
        current = self.root

        for part in parts:
            if part in ("", "."):
                continue
            if part == "..":
                # Not implemented: parent traversal
                continue
            child = current.get_child(part)
            if child is None:
                if create_missing:
                    child = FileSystemNode(part, is_dir=True)
                    current.add_child(child)
                else:
                    return None
            current = child

        if expect_dir and not current.is_dir:
            return None

        return current
