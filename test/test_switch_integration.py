import json
import os
import re
import socket
import time

import pytest
from paramiko import SSHClient, AutoAddPolicy

from honeypot_utils import allocate_port
from infra.honeypot_wrapper import create_honeypot


def wait_for_port(port: int, retries: int = 10):
    for i in range(retries):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def connect_and_run_ssh_commands(
    port, username, password, commands, prompt_regex=r"\$ "
):
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username=username, password=password)
    shell = client.invoke_shell()
    shell.settimeout(5.0)

    # Read initial prompt
    buffer = ""
    while True:
        buffer += shell.recv(1024).decode()
        if re.search(prompt_regex, buffer):
            break

    results = []
    for cmd in commands:
        shell.send(cmd + "\n")
        buffer = ""
        start = time.time()
        # Read until we see the prompt again
        while True:
            buffer += shell.recv(1024).decode()
            if re.search(prompt_regex, buffer):
                break
            if time.time() - start > 5:
                raise TimeoutError(f"Timeout waiting for prompt after {cmd}")
        # Strip off the final prompt from buffer
        output = re.sub(rf".*{re.escape(cmd)}\r\n", "", buffer)
        output = re.sub(prompt_regex + r".*$", "", output).strip()
        results.append(output)
    shell.close()
    client.close()
    return results


@pytest.fixture
def ssh_honeypot():
    port = allocate_port()

    ssh_dir = os.path.abspath("test/honeypots/alpine/")
    base_conf = json.load(open(os.path.join(ssh_dir, "config.json")))

    base_conf.update(
        {
            "port": port,
            "data_file": os.path.join(ssh_dir, "data.jsonl"),
            "fs_file": os.path.join(ssh_dir, "fs_alpine.jsonl.gz"),
        }
    )

    honeypot = create_honeypot(base_conf)
    honeypot.start()
    assert wait_for_port(port), f"SSH honeypot did not start on {port}"

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
