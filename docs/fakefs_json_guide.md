
# 🗂 Creating Fake File System JSON for Honeypots

This guide explains how to extract the directory structure from Alpine or BusyBox containers and convert it into a JSON file that can be used by the SSH honeypot's FakeFS plugin.

---

## 🔧 Prerequisites

- Docker installed and running  
- Basic knowledge of shell commands

---

## 🐧 Step 1: Run the Docker Container

### Alpine:

```bash
docker run --rm -it alpine
```

### BusyBox:

```bash
docker run --rm -it busybox
```

---

## 📂 Step 2: Explore the File System

Inside the container, use shell commands to explore:

```sh
cd /
ls -R
```

Or script it:

```sh
find / -type d
```

---

## 📄 Step 3: Save Structure to a Text File

Inside the container:

```bash
find / -type d > /tmp/fs.txt
```

Then from another terminal (host machine):

```bash
docker cp <container_id>:/tmp/fs.txt ./fs.txt
```

Replace `<container_id>` with the actual container ID from `docker ps`.

---

## 🔄 Step 4: Convert to JSON

Use the following Python script to convert the file system text to a nested JSON:

```python
import json

fs = {"type": "dir", "content": {}}

with open("fs.txt") as f:
    for line in f:
        parts = line.strip("/
").split("/")
        node = fs["content"]
        for part in parts:
            if part not in node:
                node[part] = {"type": "dir", "content": {}}
            node = node[part]["content"]

with open("fs_alpine.json", "w") as out:
    json.dump({"/": fs}, out, indent=2)
```

---

## 📦 Step 5: Save and Use

Save the final JSON as `fs_alpine.json` or `fs_busybox.json`.

Place it inside the correct honeypot config folder:

```bash
test/honeypots/alpine/fs_alpine.json
test/honeypots/busybox/fs_busybox.json
```

---

## 🔄 Step 6: Automatic SQLite Conversion (No need to manually create .db)

You only need to create the `.json` file.

At runtime, honeypot will:

- Detect that `fs_file` ends with `.json`
- Automatically convert it into a temporary `.db` file using `sqlite-utils`
- Load it using `FakeFSDataStore`

So you do not need to commit or manage `.db` files in Git.

### 🛠 Script used for JSON ->️ SQLite conversion

Internally, the honeypot runs this script:

```python
# src /infra/json_to_sqlite.py

import json
import sys
from pathlib import Path
import sqlite_utils

fs_json_path, db_path = sys.argv[1], sys.argv[2]
db = sqlite_utils.Database(db_path)

with open(fs_json_path, "r", encoding="utf-8") as f:
    fs_data = json.load(f)

records = []
for path, node in fs_data.items():
    records.append({
        "path": path,
        "parent_path": str(Path(path).parent) if path != "/" else None,
        "name": Path(path).name,
        "is_dir": node["type"] == "dir",
        "permissions": node.get("permissions", "drwxr-xr-x"),
        "owner": node.get("owner", "root"),
        "size": node.get("size", 0),
        "modified_at": None,
        "content": (
            json.dumps(node.get("content", {}))
            if node["type"] == "dir" else node.get("content", "")
        ),
    })

db["fs_nodes"].insert_all(records, pk="path", alter=True)
```

---

## Example Honeypot Config

```json
{
  "type": "ssh",
  "port": 2222,
  "data_file": "test/honeypots/test_responses.jsonl",
  "system_prompt": "You are a Linux emulator",
  "model_id": "test-model",
  "fs_file": "test/honeypots/alpine/fs_alpine.json"
}

```

---

## 🧹 Git Ignore .db Files

Make sure to ignore `.db` files generated from the `.json`:

```gitignore
test/honeypots/*/*.db
```

---

## 📈 Supporting `.jsonl.gz`

Example:
```python
import gzip, json
import sqlite_utils

with gzip.open("fs_data.jsonl.gz", "rt") as f:
    db = sqlite_utils.Database("fs.db")
    db["fs_nodes"].insert_all((json.loads(line) for line in f), batch_size=1000, alter=True)
```

---

✅ You’re now ready to use JSON-configured FakeFS with auto-generated SQLite support in your honeypots!