import logging
import os
from datetime import datetime

from infra.fake_fs.filesystem import FakeFileSystem, FileSystemNode


def handle_ls(session: dict, flags: str = "") -> str:
    fs: FakeFileSystem = session["fs"]
    cwd: str = session.get("cwd", "/")
    logging.info(f"[handle_ls] Resolving path: {cwd}")

    node = fs.resolve_path(cwd, "/")
    logging.info(f"[handle_ls] Node resolved: {node}")

    if not node or not node.is_dir:
        return f"ls: cannot access '{cwd}': No such directory"

    children = node.list_children()
    logging.info(f"[handle_ls] Children: {children}")

    return "  ".join(sorted(child.strip() for child in children))


def handle_cd(session: dict, path: str) -> str:
    fs: FakeFileSystem = session["fs"]
    current_path = session.get("cwd", "/")

    for candidate in [p.strip() for p in path.split("||")]:
        new_path = normalize_path(candidate, current_path)
        node = fs.resolve_path(new_path, "/")
        if node and node.is_dir:
            session["cwd"] = new_path
            return new_path

    return f"cd: no such file or directory: {path}"


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


from textwrap import dedent


def handle_download(session, url: str) -> str:
    DOWNLOAD_DIR = os.getenv("HONEYPOT_DOWNLOAD_DIR", "/data/downloaded_files")
    fs = session["fs"]
    cwd = session.get("cwd", "/")
    filename = url.strip().split("/")[-1]
    virtual_path = normalize_path(filename, cwd)

    fs.create_file(virtual_path, content=f"# downloaded from {url}")

    # Track downloaded files
    session.setdefault("downloads", []).append({"url": url, "path": virtual_path})

    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    file_path = os.path.join(DOWNLOAD_DIR, filename)
    with open(file_path, "w") as f:
        f.write(f"# downloaded from {url}")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fake_file_size = 1234

    return (
        f"--{now}--  {url}\n"
        f"Resolving {url.split('/')[2]}... done.\r\n"
        f"Connecting to {url.split('/')[2]}|192.0.2.1|:80... connected.\r\n"
        f"HTTP request sent, awaiting response... 200 OK\r\n"
        f"Length: {fake_file_size} [text/x-shellscript]\r\n"
        f"Saving to: ‘{filename}’\r\n\n"
        f"{filename}              100%[{fake_file_size}/{fake_file_size}]   1.21K/s   in 0.01s\r\n\n"
        f"{now} (1.21 KB/s) - ‘{filename}’ saved [{fake_file_size}/{fake_file_size}]"
    )


def normalize_path(path: str, cwd: str) -> str:
    if path.startswith("/"):
        base = []
    else:
        base = [p for p in cwd.strip("/").split("/") if p]

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
