import json
import os
import socket
import time

import pytest
from paramiko import SSHClient, AutoAddPolicy

from infra.honeypot_wrapper import create_honeypot_by_folder


def wait_for_port(port: int, retries: int = 10):
    for i in range(retries):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def connect_and_run_ssh_commands(port, username, password, commands):
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username=username, password=password)
    shell = client.invoke_shell()

    output = []
    for cmd in commands:
        shell.send(cmd + "\n")
        time.sleep(0.5)
        received = shell.recv(4096).decode()
        output.append(received)

    client.close()
    return output


@pytest.fixture
def ssh_honeypot():
    ssh_dir = os.path.abspath("test/honeypots/alpine/")
    with open(os.path.join(ssh_dir, "config.json")) as f:
        port = json.load(f)["port"]

    honeypot = create_honeypot_by_folder(ssh_dir)
    honeypot.start()
    assert wait_for_port(port), "SSH honeypot did not start"

    yield honeypot

    honeypot.stop()


def load_jsonl(filepath):
    with open(filepath, "r") as f:
        return [json.loads(line.strip()) for line in f if line.strip()]


def test_fakefs_json_based(ssh_honeypot):
    ssh_port = ssh_honeypot.config["port"]
    assert wait_for_port(ssh_port), "SSH port not ready"

    test_cases = load_jsonl("test/test_fakefs_cases.jsonl")
    for i, case in enumerate(test_cases):
        response = connect_and_run_ssh_commands(
            port=ssh_port,
            username="user",
            password="pass",
            commands=[case["command"]],
        )[0]
        print(f"Response {i}: {repr(response)}")
        assert (
            case["expect"] in response
        ), f"Failed case {i}: {case['command']}\nExpected: {case['expect']}\nActual: {response}"

    print("Test complete. Main thread sleeping briefly before exiting.")
    time.sleep(2)


def test_fallback_json_based(ssh_honeypot):
    ssh_port = ssh_honeypot.config["port"]

    assert wait_for_port(ssh_port), "SSH port not ready"

    test_cases = load_jsonl("test/test_fallback_cases.jsonl")
    for i, case in enumerate(test_cases):
        response = connect_and_run_ssh_commands(
            port=ssh_port,
            username="user",
            password="pass",
            commands=[case["command"]],
        )[0]
        print(f"Response {i}: {repr(response)}")
        assert (
            case["expect"] in response
        ), f"Failed case {i}: {case['command']}\nExpected: {case['expect']}\nActual: {response}"

    print("Test complete. Main thread sleeping briefly before exiting.")
    time.sleep(2)
