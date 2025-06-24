def convert_json_to_sqlite(json_path, db_path):
    import json
    from infra.fake_fs_datastore import FakeFSDataStore

    with open(json_path) as f:
        fs_data = json.load(f)

    store = FakeFSDataStore(db_path)

    def insert_recursive(path, node):
        if node["type"] == "dir":
            store.mkdir(path)
            for name, child in node.get("content", {}).items():
                insert_recursive(path.rstrip("/") + "/" + name, child)
        else:
            store.write_file(path, content="")

    insert_recursive("/", fs_data["/"])
