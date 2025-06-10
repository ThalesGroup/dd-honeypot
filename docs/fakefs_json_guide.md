
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

✅ You’re now ready to integrate this into your SSH honeypot with FakeFS support!