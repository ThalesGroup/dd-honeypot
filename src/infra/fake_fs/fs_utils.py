import gzip
import json
from pathlib import Path

import sqlite_utils


def create_db_from_jsonl_gz(jsonl_gz_path, db_path):
    def record_generator():
        with gzip.open(jsonl_gz_path, "rt") as f:
            for line in f:
                entry = json.loads(line)
                path = entry["path"]
                yield {
                    "path": path,
                    "parent_path": str(Path(path).parent) if path != "/" else None,
                    "name": Path(path).name,
                    "is_dir": entry.get("is_dir", True),
                    "permissions": entry.get("permissions", "drwxr-xr-x"),
                    "owner": entry.get("owner", "root"),
                    "size": entry.get("size", 0),
                    "modified_at": entry.get("modified_at", None),
                    "content": entry.get("content", "{}"),
                }

    db = sqlite_utils.Database(db_path)
    db["fs_nodes"].insert_all(
        record_generator(), pk="path", batch_size=1000, alter=True
    )
