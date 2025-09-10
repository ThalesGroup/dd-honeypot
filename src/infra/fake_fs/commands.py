import logging
import os
from datetime import datetime

from infra.fake_fs.filesystem import FakeFileSystem


def format_ls_l(entry: dict) -> str:
    import datetime

    permissions = entry.get("permissions", "drwxr-xr-x")
    links = 1
    owner = entry.get("owner", "root")
    group = "root"
    size = entry.get("size", 0)

    try:
        dt = datetime.datetime.fromisoformat(entry["modified_at"])
    except Exception:
        dt = datetime.datetime(2024, 9, 26)

    date_str = dt.strftime("%b %d %Y")
    name = entry["name"]

    return f"{permissions} {links:>2} {owner:<8} {group:<8} {size:>6} {date_str} {name}"


def handle_ls(session: dict, flags: str = "") -> str:
    fs: FakeFileSystem = session["fs"]
    cwd: str = session.get("cwd", "/")
    logging.info(f"[handle_ls] Resolving path: {cwd}")

    node = fs.resolve_path(cwd, "/")
    logging.info(f"[handle_ls] Node resolved: path={node['path']} name={node['name']}")

    if not node or not node["is_dir"]:
        return f"ls: cannot access '{cwd}': No such directory"

    children = fs.list_children(cwd)
    logging.info(f"[handle_ls] {len(children)} children found under {node['path']}")

    if "-l" in flags:
        return (
            "\r\n".join(
                format_ls_l(child)
                for child in sorted(children, key=lambda c: c["name"])
            )
            + "\r\n"
        )
    else:
        return "  ".join(sorted(child["name"] for child in children)) + "\r"


def handle_cd(session: dict, path: str) -> str:
    fs: FakeFileSystem = session["fs"]
    current_path = session.get("cwd", "/")

    for candidate in [p.strip() for p in path.split("||")]:
        new_path = normalize_path(candidate, current_path)
        node = fs.resolve_path(new_path, "/")
        if node and node["is_dir"]:
            session["cwd"] = new_path
            return new_path

    return f"cd: no such file or directory: {path}"


def handle_mkdir(session: dict, path: str) -> str:
    fs: FakeFileSystem = session["fs"]
    cwd = session.get("cwd", "/")
    full_path = normalize_path(path, cwd)

    # Check if already exists
    if fs.resolve_path(full_path):
        return f"mkdir: cannot create directory '{path}': File exists"

    # Ensure parent exists and is a directory
    parent_path = os.path.dirname(full_path)
    parent_node = fs.resolve_path(parent_path)
    if not parent_node or not parent_node["is_dir"]:
        return f"mkdir: cannot create directory '{path}': No such file or directory"

    fs.mkdir(full_path)
    return ""


def handle_download(session, url: str) -> str:
    DOWNLOAD_DIR = os.getenv("HONEYPOT_DOWNLOAD_DIR", "/data/downloaded_files")
    fs = session["fs"]
    logging.info(f"[handle_download] session['fs'] type: {type(fs)}")
    if hasattr(fs, "fakefs"):  # e.g., FakeFSDataHandler
        logging.warning(
            "[handle_download] session['fs'] is a handler, unwrapping .fakefs"
        )
        fs = fs.fakefs
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
