# Delete a Single Record from Honeypot SQLite DB (Inside Docker)

## 1. Exec into the container:
``` bash
  docker exec -it dd-honeypot sh
```

## 2. Install SQLite (if not installed):
```bash
  apk add --no-cache sqlite
```

## 3. Open the SQLite Database:
```bash
  sqlite3 /data/honeypot/mysql/data_store.db
```

## 4. Delete a specific record:
```bash
  DELETE FROM honeypot_data WHERE command = 'whoami';
  ```
```bash
  COMMIT;
```

## 5. Verify deletion:
```bash
  SELECT * FROM honeypot_data WHERE command = 'whoami';
```

## 6. Exporting stored data to JSON (Not sure if works for all versions):
```bash
  sqlite3 /data/honeypot/mysql/data_store.db \
  -cmd ".mode json" \
  "SELECT * FROM honeypot_data;" > export.json
```

Inspect:

```bash
  docker cp dd-honeypot:/export.json ./honeypot_dump.json
```