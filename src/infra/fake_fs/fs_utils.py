import gzip
import json
import sqlite_utils


def create_db_from_jsonl_gz(jsonl_gz_path, db_path):
    with gzip.open(jsonl_gz_path, "rt") as f:
        db = sqlite_utils.Database(db_path)
        db["fs_nodes"].insert_all(
            (json.loads(line) for line in f),
            batch_size=1000,
            alter=True,
        )
