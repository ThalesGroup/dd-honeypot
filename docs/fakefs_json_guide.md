# 🗂️ Creating a Fake File System for Honeypots

This guide shows how to extract a container’s file system and convert it into a compressed JSONL file used by the honeypot’s FakeFS plugin.

---

## 🔧 Requirements

- Docker installed and running

---

## 📁 Step 1: Run the Docker Container and Extract File System Structure

Use Docker to extract the directory tree and save it compressed:

```bash
  docker run -v ${PWD}:/fakefs-output/ --rm alpine sh -c "find / -type d | gzip > /fakefs-output/fs.txt.gz"
```

This creates a `fs.txt.gz` file containing directory paths.

---

## 🔄 Step 2: Convert to `.jsonl.gz`

Use the provided script to convert the file system structure to a format consumable by the honeypot:

### 🔄 Convert text → JSONL.GZ:

```bash
  docker run -v ${PWD}:/data --rm python:3-alpine \
  python /data/src/infra/fake_fs/convert_fs_txt_to_jsonl_gz.py /data/fs.txt.gz /data/fs_alpine.jsonl.gz
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