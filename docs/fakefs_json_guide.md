
# 🗂 Creating Fake File System JSON for Honeypots

This guide explains how to extract the directory structure from Alpine or BusyBox containers and convert it into a JSON file that can be used by the SSH honeypot's FakeFS plugin.

---

## 🔧 Prerequisites

- Docker installed and running  
- Basic knowledge of shell commands

---

## 📄 Run the Docker Container and extract the File system

Run an Alpine container and save the file system structure to a text file:

```bash
  docker run -v ${PWD}:/fakefs-output/ --rm alpine sh -c "find / -type d > /fakefs-output/fs.txt"
```

---

## 🔄 Convert to JSON

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

Otherwise, create a file in the container and convert it.

Example using a containerized Python environment:

```bash
  docker run -v ${PWD}:/data --rm python:alpine python /data/convert_to_json.py
```

---

## 💾 Supported Formats:

- `.json`: A nested JSON structure representing the fake file system. This is the preferred and editable format.


- `.jsonl.gz`: Compressed newline-delimited JSON, used for larger structures and efficient storage.

---

## 📦 Save and Use

Place the final `.json` or `.jsonl.gz` file in the appropriate honeypot folder, for example:


```bash
  test/honeypots/alpine/fs_alpine.json
```

Update your honeypot config to point to this file via the `fs_file` parameter.

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

✅ You're now ready to simulate a real Alpine Linux file system using FakeFS!