import pytest
import paramiko
import socket
import time
import logging
from src.ssh_honeypot import SSHHoneypot

logging.basicConfig(level=logging.INFO)


def wait_for_ssh(port, timeout=30):
    """Wait until SSH service is fully responsive"""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with paramiko.SSHClient() as client:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    'localhost',
                    port=port,
                    username='test',
                    password='test',
                    timeout=5,
                    banner_timeout=15,
                    auth_timeout=15
                )
                return True
        except (socket.error, paramiko.SSHException):
            time.sleep(0.5)
    return False


@pytest.fixture
def honeypot():
    hp = SSHHoneypot(port=0).start()
    assert wait_for_ssh(hp.port), "Honeypot failed to become responsive"
    yield hp
    hp.stop()
    time.sleep(0.5)


def test_basic_command_execution(honeypot):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            'localhost',
            port=honeypot.port,
            username='test',
            password='test',
            timeout=10,
            banner_timeout=15,
            auth_timeout=15
        )

        _, stdout, _ = client.exec_command('test-command')
        output = stdout.read().decode()
        assert 'command not found' in output
        assert stdout.channel.recv_exit_status() == 1

    finally:
        client.close()


def test_interactive_shell(honeypot):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            'localhost',
            port=honeypot.port,
            username='user',
            password='pass',
            timeout=10,
            banner_timeout=15,
            auth_timeout=15
        )

        channel = client.invoke_shell()
        channel.settimeout(5)

        # Wait for prompt
        channel.recv(1024)  # Banner
        channel.recv(1024)  # Prompt

        channel.send('ls\n')
        output = b''
        while b'$ ' not in output:
            output += channel.recv(1024)

        assert b'command not found' in output

        channel.send('exit\n')
        exit_status = channel.recv_exit_status()
        assert exit_status == 0

    finally:
        client.close()