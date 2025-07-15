import json
import os
import socket
import time

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


def test_switch_between_ssh_and_mysql():
    ssh_dir = os.path.abspath("honeypots/mysql_ssh/ssh")
    mysql_dir = os.path.abspath("honeypots/mysql_ssh/mysql")

    with open(os.path.join(ssh_dir, "config.json")) as f:
        ssh_port = json.load(f)["port"]

    with open(os.path.join(mysql_dir, "config.json")) as f:
        mysql_port = json.load(f)["port"]

    ssh = create_honeypot_by_folder(ssh_dir)
    mysql = create_honeypot_by_folder(mysql_dir)

    ssh.start()
    mysql.start()

    assert wait_for_port(ssh_port), "SSH port not ready"
    assert wait_for_port(mysql_port), "MySQL port not ready"

    commands_1 = [
        "whoami",  # SSH
        "mysql -u root -p",  # triggers switch to MySQL
        "select 1",  # MySQL
        "exit",  # switch back to SSH
    ]

    commands_2 = ["ls", "exit"]  # SSH again  # close session

    responses = []
    responses += connect_and_run_ssh_commands(
        port=ssh_port, username="user", password="pass", commands=commands_1
    )

    # reconnect to SSH
    responses += connect_and_run_ssh_commands(
        port=ssh_port, username="user", password="pass", commands=commands_2
    )

    print("\n".join(f"Response {i}: {repr(r)}" for i, r in enumerate(responses)))

    assert any(
        "whoami" in r or "root" in r.lower() for r in responses
    ), "Missing output for whoami"

    assert any("mysql" in r.lower() for r in responses), "Did not switch to MySQL"

    assert any(
        "select 1" in r or "1" in r for r in responses
    ), "MySQL query response missing"

    assert any(
        "ls" in r or "bin" in r.lower() for r in responses
    ), "Did not switch back to SSH"

    ssh.stop()
    mysql.stop()


def load_jsonl(filepath):
    with open(filepath, "r") as f:
        return [json.loads(line.strip()) for line in f if line.strip()]


def test_fakefs_json_based():
    ssh_dir = os.path.abspath("honeypots/mysql_ssh/ssh")
    with open(os.path.join(ssh_dir, "config.json")) as f:
        ssh_port = json.load(f)["port"]

    ssh = create_honeypot_by_folder(ssh_dir)
    ssh.start()

    assert wait_for_port(ssh_port), "SSH port not ready"

    test_cases = load_jsonl("test_fakefs_cases.jsonl")
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

    ssh.stop()
    print("Test complete. Main thread sleeping briefly before exiting.")
    time.sleep(2)


def test_fallback_json_based():
    ssh_dir = os.path.abspath("honeypots/mysql_ssh/ssh")
    with open(os.path.join(ssh_dir, "config.json")) as f:
        ssh_port = json.load(f)["port"]

    ssh = create_honeypot_by_folder(ssh_dir)
    ssh.start()

    assert wait_for_port(ssh_port), "SSH port not ready"

    test_cases = load_jsonl("test_fallback_cases.jsonl")
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

    ssh.stop()
    print("Test complete. Main thread sleeping briefly before exiting.")
    time.sleep(2)
