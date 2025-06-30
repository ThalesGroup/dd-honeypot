# 🗂️ Creating a Fake File System for Honeypots

This guide shows how to extract a container’s file system and convert it into a compressed JSONL file used by the honeypot’s FakeFS plugin.

---

## 🔧 Requirements

- Docker installed and running  
- Basic knowledge of shell commands
- Python 3.x

---

## 📁 Step 1: Run the Docker Container and Extract File System Structure

Use Docker to extract the directory tree and save it compressed:

```bash
  docker run -v ${PWD}:/fakefs-output/ --rm alpine sh -c "find / -type d | gzip > /fakefs-output/fs.txt.gz"
```

This creates a `fs.txt.gz` file containing directory paths.

---

## 🔄 Step 2: Convert to `.jsonl.gz`

Use this Python script to convert the extracted text into `.jsonl.gz` format:

```python
import json

fs = {"type": "dir", "content": {}}

with open("fs.txt") as f:
    for line in f:
        parts = line.strip("/\n").split("/")
        node = fs["content"]
        for part in parts:
            if part not in node:
                node[part] = {"type": "dir", "content": {}}
            node = node[part]["content"]

with open("fs_alpine.json", "w") as out:
    json.dump({"/": fs}, out, indent=2)
```

Save this as `convert_fs_to_jsonl.py` and run:

```bash
  python convert_fs_to_jsonl.py
```

---

## 📦 Step 3: Use in Honeypot

Place the final `fs.jsonl.gz` in your honeypot folder, e.g.:

```
test/honeypots/alpine/fs.jsonl.gz
```

```json
{
  "type": "ssh",
  "port": 2222,
  "data_file": "test/honeypots/test_responses.jsonl",
  "system_prompt": "You are a Linux emulator",
  "model_id": "test-model",
  "fs_file": "fs.jsonl.gz"
}
```

---

✅ You’re now ready to simulate a real container file system inside the honeypot!