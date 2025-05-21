# DataTrap - Data Driven LLM based Honeypot

DataTrap is an innovative and extensible honeypot system that emulates realistic behavior across TCP, HTTP, SSH, and various database protocols. Designed to simulate web applications, IoT devices, and databases, DataTrap goes beyond traditional honeypots by combining recorded payloads, metadata, and a large language model (LLM) to dynamically generate responses that closely mimic genuine application output.

This unique approach not only effectively deceives attackers but also delivers actionable insights—all while maintaining high performance, low cost of ownership, and operational efficiency. The system supports multiple applications and their different versions, and allows selective emulation of application components. Its modular architecture enables seamless extension of the network protocol layer to support additional applications and services over time.

At the heart of DataTrap is a continuously evolving dataset, which powers the LLM-based response generation. This dataset is central to the system’s effectiveness and is actively maintained as part of the framework. LLM-generated responses are automatically integrated into the dataset, ensuring that the system adapts to emerging threats and stays up to date.

DataTrap is open-source, encouraging community contributions to enrich both the dataset and system capabilities. To simplify deployment, it is packaged as a Docker image, allowing users to run the honeypot system as a single container in any environment with minimal setup.

## Features

- Mimics real application behavior for HTTP, HTTPS, SSH, and database access
- Uses recorded application payloads, metadata, and a large language model (LLM)
- Dynamically generates responses indistinguishable from real application outputs
- Provides actionable intelligence
- High performance and cost efficiency
- Easy to install (single container installation) and supports multiple applications and versions

# Architecture
The honeypot system is build on a modular architecture, with the following components:
- Network infrastructure, which support basic protocols like HTTP, HTTPS, SSH
- Specific application network protocol and handshake implementation, based on 3rd party libraries
- Dataset and lookup functions. The dataset contains the application payloads and metadata
- Large language model (LLM) for generating responses, using the dataset as a RAG (Retrieval-Augmented Generation) model


## Dataset

The dataset powering the framework is the most critical component of the system. It is designed to evolve continuously and will be maintained as part of the tool, ensuring that the system stays relevant and effective against emerging threats. The tool is open-source, enabling community contributions to enrich the dataset and enhance functionality. Operations for adding and updating the dataset data are an integral part of the framework.

The dataset is a set of files, each containing a set of payloads for a specific application and version. Each payload consists of a request and a response. The request is the input to the application, and the response is the output. Each payload can also be context aware (like current directory in a file system, or data added to the database), and can contain placeholders for dynamic values (like user name, host name, etc.).

A dataset file can also link to other dataset files, allowing a honeypot to use multiple datasets (like common MySql commands, and ones related to specific versions) for different applications and versions.

Simple dataset file example:
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
## LLM Interaction and dataset update

The large language model (LLM) enables the generation of realistic responses. When a honeypot gets a request, there is a lookup in the dataset to find the most relevant response. If the response is not found, the LLM generates a response based on the request. The generated response is then stored in a dedicated log, which is later merged into the dataset. This allows incremental building of the dataset and ensures that the system continuously improves its responses.

LLM access is done by API, the following LLM

## Configuration folder

The configuration folder defines the honeypots and port mappings. Each honeypot has an ID, type, port and other configuration details.

## Installation

For ease of deployment, the tool is provided as a Docker image, allowing users to quickly install and operate the honeypot system in any environment.

### Using Docker

#### Pull the Docker image:

```sh
docker pull ghcr.io/thalesgroup/dd-honeypot
```
Run the Docker container:
```sh
docker run -d -p 80:80 -p 2222:2222 ghcr.io/thalesgroup/dd-honeypot
```
Run the Docker container with a configuration file:
```sh
docker run -d -p 80:80 -p 443:443 -p 2222:2222 -v /host/path/honeypot.conf:/etc/honeypot/honeypot.conf:ro ghcr.io/thalesgroup/dd-honeypot
```

### Quick Installation on an AWS EC2 Instance

1. Create an instance role with permissions to write to CloudWatch logs
2. Create a security group with open ports according to your honeypots configuration
3. Bring up an EC2 instance with the instance role and the security group
4. Install docker and run the Docker container as described above. Add the following parameters to the docker run command:
```sh
docker run -it --log-driver=awslogs --log-opt awslogs-region=us-east1 --log-opt awslogs-group=yourLogGroup --log-opt awslogs-create-group=true ghcr.io/thalesgroup/dd-honeypot
```

Other logging options are provided in the configuration file. See the [logging readme](docs/logging-readme.md) for more details.