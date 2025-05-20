from infra.fake_fs.filesystem import FakeFileSystem, FileSystemNode


def handle_ls(session: dict, flags: str = "") -> str:
    import logging

    fs: FakeFileSystem = session["fs"]
    cwd: str = session.get("cwd", "/")
    logging.info(f"[handle_ls] Resolving path: {cwd}")

    node = fs.resolve_path(cwd, "/")

    logging.info(f"[handle_ls] Node resolved: {node}")
    if not node or not node.is_dir:
        return f"ls: cannot access '{cwd}': No such directory"

    children = node.list_children()
    logging.info(f"[handle_ls] Children: {children}")

    if "-l" in flags:
        # Simulate a fake "ls -l" output
        return "\n".join(
            f"drwxr-xr-x 1 user group 0 Jan 1 00:00 {child}" for child in children
        )
    else:
        return "\n".join(children)


def handle_cd(session: dict, path: str) -> str:
    fs: FakeFileSystem = session["fs"]
    current_path = session.get("cwd", "/")
    target = fs.resolve_path(path, current_path)
    if not target or not target.is_dir:
        return f"cd: no such file or directory: {path}"
    session["cwd"] = normalize_path(path, current_path)
    return ""


def handle_mkdir(session: dict, path: str) -> str:
    fs: FakeFileSystem = session["fs"]
    cwd = session.get("cwd", "/")
    parts = path.strip("/").split("/")
    name = parts[-1]
    parent_path = "/".join(parts[:-1]) or cwd

    parent_node = fs.resolve_path(parent_path, cwd)
    if not parent_node or not parent_node.is_dir:
        return f"mkdir: cannot create directory '{path}': No such file or directory"

    if name in parent_node.children:
        return f"mkdir: cannot create directory '{path}': File exists"

    parent_node.add_child(FileSystemNode(name, is_dir=True))
    return ""


def normalize_path(path: str, cwd: str) -> str:
    if path.startswith("/"):
        base = []
    else:
        base = cwd.strip("/").split("/")

    parts = path.strip("/").split("/")
    for part in parts:
        if part in ("", "."):
            continue
        elif part == "..":
            if base:
                base.pop()
        else:
            base.append(part)

    return "/" + "/".join(base)
