import sys
import gzip
import json


def convert(txt_path, out_path):
    with open(txt_path, "r") as fin, gzip.open(out_path, "wt") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            parts = line.strip("/").split("/")
            name = parts[-1] or "/"
            path = "/" + "/".join(parts)
            parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
            node = {
                "path": path,
                "parent_path": None if path == "/" else parent_path,
                "name": name,
                "is_dir": True,
                "permissions": "drwxr-xr-x",
                "owner": "root",
                "size": 0,
                "modified_at": None,
                "content": None,
            }
            fout.write(json.dumps(node) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python fs_txt_to_jsonl_gz.py fs.txt fs.jsonl.gz")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
