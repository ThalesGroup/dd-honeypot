## How to Create a Honeypot in DataTrap

This document explains how to define and organize honeypots in the DataTrap honeypot system. The system supports different protocol types like SSH, HTTP, Telnet, and MySQL. Each honeypot has a configuration file that defines its behavior, prompts, LLM model usage, and which port it listens on.

---

## Key Features

* **LLM-backed emulation**: Mimics real application behavior using an AI model.
* **Dynamic dataset**: Automatically updated with attacker interactions.
* **Multi-protocol support**: HTTP, SSH, Telnet, MySQL, and more.
* **Docker deployment**: Run anywhere with ease.
* **Decoy intelligence**: Provides insight into attacker behavior.
* **Modular architecture**: Add honeypots without changing core logic.

---

## Architecture Overview

```
+-----------------------------+
|        Incoming Traffic     |
+-----------------------------+
             ↓
+-----------------------------+
|     Protocol Dispatcher      | ← e.g., HTTP, SSH, MySQL
+-----------------------------+
             ↓
+-----------------------------+
|     Honeypot Handler         | ← LLM + Dataset-based Simulation
+-----------------------------+
             ↓
+-----------------------------+
|       Dataset Lookup         | ← Matches past payloads/responses
+-----------------------------+
             ↓
+-----------------------------+
|  LLM Generation (Fallback)   | ← When no match found in dataset
+-----------------------------+
```

---

## Honeypots Directory Structure

All honeypots and their configurations are defined under the `honeypots/` directory.

```
honeypots/
├── alpine/
│   ├── config.json
│   ├── data.jsonl
│   └── fs_alpine.json
├── boa_server_http-config.json
├── busybox-config.json
├── dlink_telnet/
│   ├── config.json
│   └── alpine_fs_small.json
├── mysql-config.json
├── php_my_admin-config.json
```

Each honeypot **must** define its behavior in a `config.json` (or `*-config.json`) file and may include:

* `data.jsonl`: Known request/response pairs
* `fs_file`: Virtual file system (for CLI-based honeypots like SSH or Telnet)

---

## Honeypot Configuration Format

All honeypots should follow a standard configuration schema, with the following fields:

### Common Fields (Required)

* `type`: One of `ssh`, `http`, `telnet`, or `mysql`
* `name`: Optional display name
* `port`: Port to bind the honeypot
* `model_id`: The LLM model used (e.g., Claude, GPT)
* `data_file`: Dataset file containing request-response pairs
* `system_prompt`: Instructs the LLM how to behave

### Optional Fields (Based on Type)

* `prompt_template`, `shell-prompt`: For SSH/Telnet CLI simulation
* `fs_file`: For simulating file system-based responses (e.g., Alpine/BusyBox)
* `telnet`: Telnet-specific prompts and banners
* `dialect`: For SQL-type honeypots like `mysql`

### Example: Alpine (SSH)

```json
{
  "type": "ssh",
  "name": "Alpine Linux Honeypot",
  "prompt_template": "${{username}}@alpine:${{cwd}}$ ",
  "shell-prompt": "honeypot@fakevm:~$ ",
  "data_file": "data.jsonl",
  "fs_file": "fs_alpine.json",
  "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
  "system_prompt": "You are a terminal on Alpine Linux...",
  "port": 2224
}
```

### Example: MySQL

```json
{
  "type": "mysql",
  "port": 13306,
  "dialect": "mysql",
  "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
  "data_file": "honeypots/mysql/data.jsonl",
  "system_prompt": [
    "You are a MySQL server.",
    "Return only JSON array of objects."
  ]
}
```

---

## Creating a New Honeypot

To add a new honeypot in the system, follow these structured steps:

### 1. Choose the Honeypot Type

Decide which kind of service you want to simulate:

* **ssh**: Terminal-based access (e.g., Alpine, BusyBox)
* **http**: Web-based applications (e.g., phpMyAdmin)
* **telnet**: IoT or embedded devices (e.g., routers)
* **mysql**: Database simulation

### 2. Create Directory or Config File

Inside the `honeypots/` directory, do one of the following:

* Create a new subdirectory (e.g., `honeypots/mydevice/`)
* Or create a new config file directly (e.g., `honeypots/nginx-config.json`)

> **Note:** The folder or file must include a valid `config.json` (or `*-config.json`).

### 3. Write the Configuration

Use the standard schema shown in the documentation. Required fields typically include:

* `type`
* `port`
* `model_id`
* `system_prompt`

Other fields depending on protocol (e.g., `fs_file`, `dialect`, `prompt_template`)

Use realistic prompts that match the device or software being emulated.

### 4. Add Dataset (Optional but Recommended)

Create a `data.jsonl` file in the same directory. This file contains known request-response pairs to reduce unnecessary LLM usage.

Each line is a valid JSON object with `request` and `response` fields:

```json
{
  "request": "GET /admin",
  "response": "<html><h1>403 Forbidden</h1></html>"
}
```

### 5. (Optional) Add File System (for SSH/Telnet Honeypots)

If you're simulating a shell or device that supports command-line interaction:

Add a virtual file system file such as `fs_mysystem.json`

This lets commands like `ls`, `cat`, and `cd` work realistically.

### 6. Update Port Mappings

Ensure the port defined in your `config.json`:

* Does **not** conflict with other honeypots
* Is exposed properly in your Docker or orchestration setup using `-p <host>:<container>`

### 7. Test Locally

Before deploying, test your honeypot locally:

* Use tools like `curl`, `telnet`, `mysql`, or `ssh` to connect
* Confirm that known inputs return the expected dataset results
* Check that unknown inputs are handled by the LLM fallback
* Review logs to validate realistic and non-revealing behavior

---

## Installation

### Run with Docker

```bash
docker pull ghcr.io/thalesgroup/dd-honeypot

docker run -d -p 80:80 -p 2222:2222 ghcr.io/thalesgroup/dd-honeypot
```

### Custom Configuration

```bash
docker run -d \
  -p 80:80 -p 443:443 -p 2222:2222 \
  -v /host/path/honeypot.conf:/etc/honeypot/honeypot.conf:ro \
  ghcr.io/thalesgroup/dd-honeypot
```

### On AWS EC2

1. Create instance role with CloudWatch logging permissions
2. Open necessary ports (e.g., 22, 80, 443, 13306, etc.)
3. Launch Docker container with log driver:

```bash
docker run -it \
  --log-driver=awslogs \
  --log-opt awslogs-region=us-east-1 \
  --log-opt awslogs-group=yourLogGroup \
  --log-opt awslogs-create-group=true \
  ghcr.io/thalesgroup/dd-honeypot
```

---

## Dataset & LLM Behavior

* All honeypots first attempt a lookup in the `data.jsonl` file.
* If no match is found, the LLM generates a response using the `system_prompt`.
* Generated responses are logged and can later be added to the dataset.
* Example dataset entry:

```json
{
  "request": "SELECT * FROM users;",
  "response": [
    {"id": 1, "username": "admin", "email": "admin@example.com"},
    {"id": 2, "username": "guest", "email": "guest@example.com"}
  ]
}
```

---

## Adding a New Honeypot (Quick Summary)

1. Create a folder or config file in `honeypots/`
2. Define a valid `config.json` with appropriate fields
3. Prepare `data.jsonl` with simulated interactions
4. (Optional) Add `fs_file` if CLI/file-system is required
5. Update Docker port mappings if needed
