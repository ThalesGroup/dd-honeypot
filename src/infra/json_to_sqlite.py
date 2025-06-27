import json
from pathlib import Path

import sqlite_utils


def flatten_fs(node, current_path="/", records=None):
    if records is None:
        records = []

    records.append(
        {
            "path": current_path,
            "parent_path": (
                str(Path(current_path).parent) if current_path != "/" else None
            ),
            "name": Path(current_path).name or "/",
            "is_dir": node["type"] == "dir",
            "permissions": node.get("permissions", "drwxr-xr-x"),
            "owner": node.get("owner", "root"),
            "size": node.get("size", 0),
            "modified_at": None,
            "content": (
                json.dumps(node.get("content", {}))
                if node["type"] == "dir"
                else node.get("content", "")
            ),
        }
    )

    if node["type"] == "dir":
        for name, child in node.get("content", {}).items():
            child_path = (
                str(Path(current_path) / name) if current_path != "/" else f"/{name}"
            )
            flatten_fs(child, child_path, records)

    return records


def convert_json_to_sqlite(fs_json_path, db):
    with open(fs_json_path, "r", encoding="utf-8") as f:
        fs_data = json.load(f)

    # Ensure root ("/") is present
    root = fs_data["/"] if "/" in fs_data else {"type": "dir", "content": fs_data}

    records = flatten_fs(root, "/")

    db["fs_nodes"].insert_all(records, pk="path", alter=True)


if __name__ == "__main__":
    import sys

    fs_json_path, db_path = sys.argv[1], sys.argv[2]
    db = sqlite_utils.Database(db_path)
    convert_json_to_sqlite(fs_json_path, db)
