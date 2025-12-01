# Redis Honeypot

The Redis honeypot emulates a realistic Redis server. It captures commands, maintains in-memory state, and responds to common administrative and keyspace commands. It supports the Redis Serialization Protocol (RESP) and integrates with a dataset or LLM for fallback responses.

## Features

-   **Stateful Storage**: Remembers keys set during the session (in-memory).
-   **Multi-Database**: Supports `SELECT` to switch between isolated databases (DB 0, DB 1, etc.).
-   **Authentication**: Accepts `AUTH` commands (logs the password, always allows access).
-   **Keyspace Management**: Supports `SET`, `GET`, `DEL`, and `KEYS` (listing keys).
-   **Server Info**: Provides a realistic, dynamic `INFO` response (uptime, memory, etc.).
-   **Fallback**: Uses `data.jsonl` or an LLM for commands not natively implemented.

## Configuration

To run the Redis honeypot, you need a folder containing a `config.json` and a `data.jsonl` file.

### config.json

```json
{
  "name": "redis_honeypot",
  "type": "redis",
  "port": 6379,
  "data_file": "data.jsonl",
  "system_prompt": "You are a Redis server. Respond to commands in the Redis Serialization Protocol (RESP) format. For example, for a simple string response, start with '+', for an error '-', for an integer ':', and for bulk strings '$'. If the user asks for keys or data that doesn't exist, return a null bulk string '$-1\\r\\n'. Mimic a standard Redis instance.",
  "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0"
}
```

### data.jsonl

The dataset maps commands to responses. Note that the key for the input is `command`.

```json lines
{"command": "PING", "response": "+PONG\\r\\n"}
```

## Running the Honeypot

You can run the honeypot using the `honeypot_main.py` script, pointing it to your configuration folder.

```bash
# Assuming you are in the root of the repo
export PYTHONPATH=$PYTHONPATH:$(pwd)/src
python3 src/honeypot_main.py test/honeypots/redis
```

## Testing

You can test the honeypot using `redis-cli` to verify its realistic behavior.

### Example Session

```bash
$ redis-cli -p 6379
127.0.0.1:6379> PING
PONG
127.0.0.1:6379> AUTH supersecret
OK
127.0.0.1:6379> SET user:1 "Alice"
OK
127.0.0.1:6379> SET user:2 "Bob"
OK
127.0.0.1:6379> KEYS *
1) "user:1"
2) "user:2"
127.0.0.1:6379> GET user:1
"Alice"
127.0.0.1:6379> DEL user:1
(integer) 1
127.0.0.1:6379> KEYS *
1) "user:2"
127.0.0.1:6379> SELECT 1
OK
127.0.0.1:6379[1]> KEYS *
(empty array)
127.0.0.1:6379[1]> SET secret "hidden"
OK
127.0.0.1:6379[1]> SELECT 0
OK
127.0.0.1:6379> KEYS *
1) "user:2"
127.0.0.1:6379> SELECT 1
OK
127.0.0.1:6379[1]> GET secret
"hidden"
127.0.0.1:6379[1]> INFO
# Server
redis_version:6.2.6
os:Linux
arch_bits:64
multiplexing_api:epoll
uptime_in_seconds:172
uptime_in_days:0
# Clients
connected_clients:1
# Memory
used_memory:1024000
used_memory_human:1.00M
# Persistence
loading:0
# Stats
total_connections_received:1
total_commands_processed:1
# Replication
role:master
connected_slaves:0
# CPU
used_cpu_sys:0.50
used_cpu_user:0.50
# Keyspace
db1:keys=1,expires=0,avg_ttl=0
```

### Using Netcat (nc)

If you don't have `redis-cli`, you can use `nc`.

```bash
printf "PING\r\n" | nc localhost 6379
```