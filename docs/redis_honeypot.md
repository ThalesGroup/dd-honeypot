# Redis Honeypot

The Redis honeypot emulates a Redis server, capturing commands and responding using a dataset or an LLM fallback. It supports the Redis Serialization Protocol (RESP) and handles common commands like `PING`, `SET`, `GET`, and `INFO`.

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
{"command": "SET test 123", "response": "+OK\\r\\n"}
{"command": "GET test", "response": "$3\\r\\n123\\r\\n"}
```

## Running the Honeypot

You can run the honeypot using the `honeypot_main.py` script, pointing it to your configuration folder.

```bash
# Assuming you are in the root of the repo
export PYTHONPATH=$PYTHONPATH:$(pwd)/src
python3 src/honeypot_main.py test/honeypots/redis
```

## Testing

You can test the honeypot using `redis-cli` or `nc` (Netcat).

### Using redis-cli

If you have `redis-cli` installed:

```bash
redis-cli -p 6379
127.0.0.1:6379> PING
PONG
127.0.0.1:6379> SET mykey "hello world"
OK
127.0.0.1:6379> GET mykey
"hello world"
```

### Using Netcat (nc)

If you don't have `redis-cli`, you can use `nc`. Note that you should use `\r\n` line endings for best compatibility, although the honeypot is lenient with `\n`.

```bash
# PING
printf "PING\r\n" | nc localhost 6379

# SET
printf "SET foo bar\r\n" | nc localhost 6379

# GET
printf "GET foo\r\n" | nc localhost 6379
```