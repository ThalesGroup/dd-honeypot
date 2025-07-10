# Honeypot Configuration Guide

This guide explains how to configure individual honeypots in the DataTrap honeypot system. Each honeypot is defined using a JSON configuration file located under the `honeypots/` directory.

---

## Directory Structure

All honeypots live in the `honeypots/` folder. Each honeypot can be defined in:

* A dedicated folder with `config.json`
  *(e.g., `honeypots/alpine/config.json`)*
* Or as a standalone config file
  *(e.g., `honeypots/php_my_admin-config.json`)*

Typical contents:

```
honeypots/
├── alpine/
│   ├── config.json
│   ├── data.jsonl
│   └── fs_alpine.json
├── mysql-config.json
├── php_my_admin-config.json
```

---

## Configuration Schema

Each honeypot config must include the following fields:

###  Required Fields

| Field           | Description                                     |
| --------------- | ----------------------------------------------- |
| `type`          | Protocol type: `ssh`, `http`, `telnet`, `mysql` |
| `port`          | Port to listen on                               |
| `model_id`      | LLM model used for fallback generation          |
| `data_file`     | Path to JSONL file with request/response pairs  |
| `system_prompt` | Instructions to guide LLM behavior              |

---

###  Optional Fields (Based on Type)

| Field             | Description                                                |
| ----------------- | ---------------------------------------------------------- |
| `name`            | Display name of the honeypot                               |
| `prompt_template` | Shell prompt format (for SSH/Telnet CLI simulation)        |
| `shell-prompt`    | Fixed prompt string (used by some CLI honeypots)           |
| `fs_file`         | JSON file defining virtual file system for CLI honeypots   |
| `dialect`         | SQL dialect (e.g., `mysql`, `postgresql`) for DB honeypots |

---

## Example Configurations

###  SSH Honeypot (Alpine)

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

---

###  MySQL Honeypot

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

## Steps to Add a New Honeypot

1. **Create a Config**
   Inside `honeypots/`, create a folder or a new `*-config.json` file.

2. **Fill Required Fields**
   Use the schema and examples above to define `type`, `port`, `model_id`, etc.

3. **Add Dataset**
   Create a `data.jsonl` file with request-response pairs like:

   ```json
   {
     "request": "GET /admin",
     "response": "<html><h1>403 Forbidden</h1></html>"
   }
   ```

4. **(Optional) Add File System**
   For CLI honeypots (like SSH/Telnet), add an `fs_file` such as `fs_busybox.json`.

5. **Port Mapping**
   Make sure the `port` in config:

   * Is unique (not already used)
   * Is exposed properly in Docker with `-p <host>:<container>`

---

## Notes

* All honeypot logic relies first on `data.jsonl`. If no match is found, LLM is used.
* You can reuse `model_id` and prompts across multiple honeypots.
* Dataset entries grow automatically as new interactions are logged.

---

For architecture, Docker deployment, and feature overview, refer to the [README.md](../README.md) file.
