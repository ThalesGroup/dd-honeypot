import logging
import os
import socket
import time
from pathlib import Path
from time import sleep

import paramiko

_PROJECT_FOLDER = Path(os.path.dirname(os.path.abspath(__file__))).parent.absolute()


def get_project_folder() -> str:
    return str(_PROJECT_FOLDER)


def init_env_from_file():
    full_file_name = os.path.join(get_project_folder(), "config", "aws.env.list")
    if os.path.exists(full_file_name):
        logging.info(f"Going to set env variables from file: {full_file_name}")
        with open(full_file_name) as f:
            for line in f:
                key, value = line.strip().split("=")
                os.environ[key] = value


def allocate_port():
    """
    allocate a dynamic port
    :return: port number
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def wait_for_port(port: int):
    retries = 3
    for i in range(1, retries + 1):
        try:
            with socket.create_connection(("0.0.0.0", port), timeout=1):
                break
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            if i < retries:
                sleep(0.5 * i)
            else:
                raise e


def connect_and_run_ssh_commands(port, username, password, commands):
    results = []
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username=username, password=password)

    chan = client.invoke_shell()
    time.sleep(1)
    chan.recv(1024)

    for cmd in commands:
        chan.send(cmd + "\n")
        time.sleep(1)
        output = chan.recv(4096).decode()
        results.append(output)

    chan.close()
    client.close()
    return results
