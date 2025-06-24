import sqlite3
import os
import time
from typing import Optional, List


class FakeFSDataStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS fs_nodes (
                    path TEXT PRIMARY KEY,
                    parent_path TEXT,
                    name TEXT,
                    is_dir BOOLEAN,
                    permissions TEXT,
                    owner TEXT,
                    size INTEGER,
                    modified_at TIMESTAMP,
                    content TEXT
                )
            """
            )
            conn.commit()

    def get_node(self, path: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM fs_nodes WHERE path = ?", (path,))
            row = cursor.fetchone()
            return (
                dict(zip([desc[0] for desc in cursor.description], row))
                if row
                else None
            )

    def list_dir(self, parent_path: str) -> List[dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM fs_nodes WHERE parent_path = ?", (parent_path,)
            )
            return [
                dict(zip([column[0] for column in cursor.description], row))
                for row in cursor.fetchall()
            ]

    def mkdir(self, path: str, permissions="drwxr-xr-x", owner="root", size=0):
        parent_path = os.path.dirname(path.rstrip("/")) or "/"
        name = os.path.basename(path)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO fs_nodes (path, parent_path, name, is_dir, permissions, owner, size, modified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    path,
                    parent_path,
                    name,
                    True,
                    permissions,
                    owner,
                    size,
                    int(time.time()),
                ),
            )
            conn.commit()

    def write_file(
        self, path: str, content: str, permissions="-rw-r--r--", owner="root"
    ):
        parent_path = os.path.dirname(path.rstrip("/")) or "/"
        name = os.path.basename(path)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO fs_nodes (path, parent_path, name, is_dir, permissions, owner, size, modified_at, content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    path,
                    parent_path,
                    name,
                    False,
                    permissions,
                    owner,
                    len(content),
                    int(time.time()),
                    content,
                ),
            )
            conn.commit()
