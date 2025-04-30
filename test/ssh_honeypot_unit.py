from concurrent.futures import ThreadPoolExecutor

import pytest
import paramiko
import socket
import time
import logging
import os
from src.ssh_honeypot import SSHHoneypot
from typing import Generator, List
from unittest.mock import patch

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurable hostname - defaults to localhost but can be overridden
HOSTNAME = os.getenv('SSH_TEST_HOST', 'localhost')


def wait_for_ssh(port: int, timeout: int = 30) -> bool:
    """Wait until SSH service is fully responsive"""
    start = time.time()
    last_exception = None

    while time.time() - start < timeout:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                HOSTNAME,
                port=port,
                username='test',
                password='test',
                timeout=5,
                banner_timeout=5,
                auth_timeout=5
            )
            client.close()
            return True
        except (socket.error, paramiko.SSHException) as e:
            last_exception = e
            time.sleep(0.5)
        finally:
            try:
                client.close()
            except:
                pass

    logger.warning(f"SSH connection failed: {last_exception}")
    return False


@pytest.fixture
def honeypot() -> Generator[SSHHoneypot, None, None]:
    """Fixture with proper resource cleanup"""
    hp = SSHHoneypot(port=0)
    try:
        hp.start()
        assert wait_for_ssh(hp.port), "Honeypot failed to become responsive"
        yield hp
    finally:
        hp.stop()
        time.sleep(1)  # Allow for cleanup


def test_basic_command_execution(honeypot: SSHHoneypot) -> None:
    from unittest.mock import patch

    with patch("src.ssh_honeypot.invoke_llm", return_value="Mocked LLM response\n"):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(
            HOSTNAME,
            port=honeypot.port,
            username='test',
            password='test',
            timeout=10,
            banner_timeout=10,
            auth_timeout=10
        )

        transport = client.get_transport()
        channel = transport.open_session(timeout=10)
        channel.exec_command("test-command")
        stdout = channel.recv(1024).decode()

        assert "Mocked LLM response" in stdout


def test_interactive_shell(honeypot: SSHHoneypot) -> None:
    """Test interactive shell with more resilient approach"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            'localhost',
            port=honeypot.port,
            username='user',
            password='pass',
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            look_for_keys=False,
            allow_agent=False
        )

        channel = client.invoke_shell()
        channel.settimeout(5)

        # Wait for welcome message
        output = b''
        start = time.time()
        while time.time() - start < 5 and b'Welcome' not in output:
            if channel.recv_ready():
                output += channel.recv(1024)

        assert b'Welcome' in output

        # Send command and get response
        channel.send('ls\n')

        output = b''
        start = time.time()
        while time.time() - start < 5 and b'file1.txt' not in output:
            if channel.recv_ready():
                output += channel.recv(1024)

        assert b'file1.txt' in output

    finally:
        client.close()


def test_invalid_auth_logging(honeypot: SSHHoneypot, caplog: pytest.LogCaptureFixture) -> None:
    """Test if invalid auth attempts are logged."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            HOSTNAME,
            port=honeypot.port,
            username='invalid',
            password='invalid',
            timeout=5
        )
    except Exception:
        pass  # Expected to fail, but we check logs
    finally:
        client.close()

    assert "Authentication: invalid:invalid" in caplog.text


def test_concurrent_connections(honeypot: SSHHoneypot):
    """Test 2 simultaneous connections with proper output handling."""
    clients: List[paramiko.SSHClient] = []

    try:
        for i in range(2):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                'localhost',
                port=honeypot.port,
                username=f"user_{i}",
                password="pass",
                timeout=10,
                banner_timeout=10,
                auth_timeout=10
            )
            clients.append(client)
            logging.info(f"Connected client {i}")

        def exec_and_read(client, command):
            _, stdout, _ = client.exec_command(command, timeout=5)
            # Wait for command to complete and read output
            output = b''
            start = time.time()
            while time.time() - start < 5:  # Max 5 seconds to read
                if stdout.channel.recv_ready():
                    output += stdout.channel.recv(4096)
                if stdout.channel.exit_status_ready():
                    break
                time.sleep(0.1)
            return output.decode()

        # Get outputs
        whoami_output = exec_and_read(clients[0], "whoami")
        ls_output = exec_and_read(clients[1], "ls")

        # Verify responses
        assert "root" in whoami_output
        assert "file1.txt" in ls_output

    finally:
        # Forcefully close all connections
        for client in clients:
            try:
                transport = client.get_transport()
                if transport and transport.is_active():
                    transport.close()
                client.close()
            except Exception as e:
                logging.warning(f"Cleanup error: {e}")