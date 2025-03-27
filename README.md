# DataLure - Data Driven LLM based Honeypot

This honeypot system mimics real application behavior for HTTP, HTTPS, SSH, and database access. Unlike traditional honeypots, this solution uses a combination of recorded application payloads, metadata, and a large language model (LLM) to dynamically generate responses that are indistinguishable from real application outputs. This approach not only deceives attackers but also provides actionable intelligence while maintaining high performance and cost efficiency. Additionally, the system is easy to install and supports multiple applications, including multiple application versions. Installation is done using a single container, without spanning additional containers like done in other honeypot systems.

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

## Configuration File

The configuration file defines the honeypots and port mappings. Each honeypot has an ID, type, and version of the system it mimics.

The ports configuration allows mapping a port to one or more honeypots. Each mapped honeypot has a weight (default is 1). The port mapping changes dynamically according to the weight. For example, if three honeypots are mapped to a single port, each one will be mapped to the port 1/3 of the time.


### Example Configuration File

```json
{
  "honeypots": [
    {
      "id": "ssh1",
      "type": "ssh",
      "version": "1.0"
    },
    {
      "id": "mysql5_7",
      "type": "mysql",
      "version": "5.7"
    },
    {
      "id": "mysql8_0",
      "type": "mysql",
      "version": "8.0"
    },
    {
      "id": "phpMyAdmin5_0_2",
      "type": "phpMyAdmin",
      "version": "5.0.2"
    }
  ],
  "ports": [
    {
      "port": 22,
      "honeypots": [
        {
          "id": "ssh1"
        }
      ]
    },
    {
      "port": 3306,
      "honeypots": ["mysql5_7", "mysql8_0"]
    },
    {
      "port": 80,
      "honeypots": ["phpMyAdmin5_0_2"]
    }
  ]
}
```

## Installation

For ease of deployment, the tool is provided as a Docker image, allowing users to quickly install and operate the honeypot system in any environment.

### Using Docker

#### Pull the Docker image:

```sh
docker pull ghcr.io/thalesgroup/datalure
```
Run the Docker container:
```sh
docker run -d -p 80:80 -p 443:443 -p 2222:2222 ghcr.io/thalesgroup/datalure
```
Run the Docker container with a configuration file:
```sh
docker run -d -p 80:80 -p 443:443 -p 2222:2222 -v /host/path/honeypot.conf:/etc/honeypot/honeypot.conf:ro ghcr.io/thalesgroup/datalure
```

### Installation on an AWS EC2 Instance

1. Create an instance role with permissions to write to CloudWatch logs
2. Create a security group with open ports according to your honeypots configuration
3. Bring up an EC2 instance with the instance role and the security group
4. Install docker and run the Docker container as described above. Add the following parameters to the docker run command:
```sh
docker run -it --log-driver=awslogs --log-opt awslogs-region=us-east1 --log-opt awslogs-group=yourLogGroup --log-opt awslogs-create-group=true ghcr.io/thalesgroup/datalure
```