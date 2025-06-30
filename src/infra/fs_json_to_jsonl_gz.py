import gzip
import json
import sys


def flatten_tree(tree, parent_path="/"):
    nodes = []
    for name, info in tree.items():
        current_path = parent_path.rstrip("/") + "/" + name
        node = {
            "path": current_path,
            "parent_path": parent_path,
            "name": name,
            "is_dir": info["type"] == "dir",
            "permissions": info.get(
                "permissions", "drwxr-xr-x" if info["type"] == "dir" else "-rw-r--r--"
            ),
            "owner": info.get("owner", "root"),
            "size": info.get("size", 0),
            "modified_at": info.get("modified_at", None),
            "content": None,  # optional for files, used in future
        }
        nodes.append(node)
        if info["type"] == "dir":
            nodes.extend(flatten_tree(info.get("content", {}), current_path))
    return nodes


def convert(json_path: str, out_path: str):
    with open(json_path, "r") as f:
        tree = json.load(f)

    nodes = flatten_tree(tree)

    with gzip.open(out_path, "wt") as f:
        root_node = {
            "path": "/",
            "parent_path": None,
            "name": "/",
            "is_dir": True,
            "permissions": "drwxr-xr-x",
            "owner": "root",
            "size": 0,
            "modified_at": None,
            "content": None,
        }
        f.write(json.dumps(root_node) + "\n")

        for node in nodes:
            f.write(json.dumps(node) + "\n")

    print(f"✅ Converted {json_path} → {out_path} with {len(nodes) + 1} entries")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python fs_json_to_jsonl_gz.py <in.json> <out.jsonl.gz>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
