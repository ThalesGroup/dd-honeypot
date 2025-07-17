# DataTrap - Data Driven LLM-based Honeypot

DataTrap is an innovative and extensible honeypot system that emulates realistic behavior across TCP, HTTP, SSH, and various database protocols. Designed to simulate web applications, IoT devices, and databases, DataTrap goes beyond traditional honeypots by combining recorded payloads, metadata, and a large language model (LLM) to dynamically generate responses that closely mimic real application behavior.

This unique approach not only effectively deceives attackers but also delivers actionable insights—all while maintaining high performance, low cost of ownership, and operational efficiency. The system supports multiple applications and their different versions, and allows selective emulation of specific components. Its modular architecture enables easy extension of the protocol layer to support new services over time.

At the heart of DataTrap is a continuously evolving dataset that powers LLM-based response generation. This dataset is actively maintained as part of the framework. When no exact match is found in the dataset, LLM-generated responses are used and logged for later review or integration. This ensures the system stays effective against emerging threats and continues to improve over time.

DataTrap is open-source and welcomes community contributions to enrich both the dataset and the system’s capabilities. Deployment is simplified through a Docker container, enabling users to run the honeypot system in any environment with minimal setup.

---

## Features

- Simulates real behavior for HTTP, HTTPS, SSH, and database protocols (e.g., MySQL)
- Uses recorded payloads, metadata, and large language models (LLMs) to generate responses
- Dynamically returns responses indistinguishable from real applications
- Captures valuable attacker insights for analysis
- High performance and cost-effective design
- Easy container-based installation, supports multiple applications and versions
- Modular design makes it easy to add or customize honeypots

---

## Architecture

The honeypot system is built using a modular architecture with the following components:

- **Network Layer**: Handles raw connections for supported protocols (HTTP, SSH, MySQL, etc.)
- **Protocol Handler**: Implements protocol-specific logic (e.g., MySQL handshake)
- **Dataset & Lookup Engine**: Maps incoming requests to known payloads and responses
- **LLM Engine**: Fallback for unknown requests using LLM with system prompts and RAG (Retrieval-Augmented Generation)

---
## Dataset
The dataset is the most critical component in the system. It evolves with usage and is designed for active maintenance and contribution. Each dataset file contains payloads for a specific application and version, where each payload includes:

- A **request**: the attacker’s input
- A **response**: the emulated reply
- Optional placeholders like `${user}` or `${host}` for dynamic substitution
- Context-aware fields (e.g., current working directory in a shell, or inserted rows in a database)

The dataset is a set of JSONL files, each containing one or more request-response pairs. These payloads can simulate different behaviors of a particular version of an application or device.

Datasets may also be layered or linked. For example, a honeypot can combine a general dataset for common MySQL queries with a version-specific dataset to reflect the exact behavior of MySQL 5.7 or 8.0. This modular structure enables reuse and fine-grained emulation.

The dataset is central to how DataTrap handles both known and unknown interactions:
- **Known requests** → matched and returned directly from the dataset.
- **Unknown requests** → handled by the LLM and logged for future inclusion in the dataset.

This continuous enrichment process ensures that DataTrap evolves with attacker behavior, and remains relevant over time.

### Example dataset file:

```json
{
  "application": "mysql",
  "version": "5.7",
  "payloads": [
    {
      "request": "DROP TABLE users;",
      "response": "Error: DROP command denied to user '${user}'@'${host}' for table 'users'"
    },
    {
      "request": "SELECT * FROM users;",
      "response": "Error: SELECT command denied to user '${user}'@'${host}' for table 'users'"
    }
  ]
}
```

---

## LLM Interaction and Dataset Update

If a request does not match an existing entry in the dataset, the system uses a large language model (LLM) to generate a realistic response. These responses are:

- Generated using the `system_prompt` configured per honeypot
- Logged in a separate file for review
- Optionally merged into the dataset for future reuse

This incremental learning model allows the honeypot to grow smarter over time while preserving a high degree of realism.

LLM access is handled via API using supported providers (e.g., OpenAI, Anthropic).

---

## Configuration Folder

The configuration folder contains the main `honeypot.conf` file, which defines:

- All honeypots to load at runtime
- Paths to their individual config files
- Global settings (e.g., logging, ports)

Each honeypot is defined with a unique ID, type, and path to its `config.json`.


---

## Installation

DataTrap is packaged as a Docker image for quick and reproducible deployment.

### Using Docker

#### Pull the Docker image

```sh
docker pull ghcr.io/thalesgroup/dd-honeypot
```

#### Run the Docker container (default setup)

```sh
docker run -d -p 80:80 -p 2222:2222 ghcr.io/thalesgroup/dd-honeypot
```

#### Run with a custom configuration

```sh
docker run -d \
  -p 80:80 -p 443:443 -p 2222:2222 \
  -v /host/path/honeypot.conf:/etc/honeypot/honeypot.conf:ro \
  ghcr.io/thalesgroup/dd-honeypot
```

---

### Quick Installation on AWS EC2

1. Create an instance role with permissions to write to CloudWatch logs
2. Create a security group with open ports (e.g., 22, 80, 443, 13306, etc.)
3. Launch an EC2 instance with the role and group
4. Install Docker and run the container:

```sh
docker run -it \
  --log-driver=awslogs \
  --log-opt awslogs-region=us-east-1 \
  --log-opt awslogs-group=yourLogGroup \
  --log-opt awslogs-create-group=true \
  ghcr.io/thalesgroup/dd-honeypot
```

### Licensing
dd-honeypot is distributed under the [Apache 2.0 License](LICENSE.md). It depends on modules that are licensed under their own open-source licenses (see the [third-party file](THIRD_PARTY.txt)).