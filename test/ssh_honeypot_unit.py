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
from unittest.mock import MagicMock

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


import pytest
import paramiko
import time
from pathlib import Path
from unittest.mock import patch

from src.infra.honeypot_wrapper import create_honeypot


@pytest.fixture
def ssh_honeypot(tmp_path: Path):
    """Fixture to create and start SSH honeypot with mock LLM fallback."""
    data_file = tmp_path / "data.jsonl"

    config = {
        "type": "ssh",
        "port": 0,
        "data_file": str(data_file),
        "system_prompt": "You are a Linux terminal emulator.",
        "model_id": "test-model"
    }

    # Patch invoke_llm before creating the honeypot
    with patch("src.infra.honeypot_wrapper.invoke_llm", return_value="Mocked LLM response\n"):
        honeypot = create_honeypot(config)
        honeypot.start()
        time.sleep(0.1)
        yield honeypot
        honeypot.stop()


def test_basic_command_execution(ssh_honeypot):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect("localhost", port=ssh_honeypot.port, username="test", password="test")

    transport = client.get_transport()
    channel = transport.open_session()
    channel.exec_command("test-command")

    output = b""
    start = time.time()
    while time.time() - start < 5:
        if channel.recv_ready():
            output += channel.recv(1024)
        if channel.exit_status_ready():
            break
        time.sleep(0.1)

    decoded = output.decode()
    assert "Mocked LLM response" in decoded
    assert channel.recv_exit_status() == 0
    client.close()


def test_interactive_shell(ssh_honeypot) -> None:
    """Test interactive shell with more resilient approach"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            'localhost',
            port=ssh_honeypot.port,
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

        assert b'file1.txt' in output or b'Mocked LLM response\n\r\nuser@honeypot:~$ ' in output

    finally:
        client.close()


def test_invalid_auth_logging(ssh_honeypot, caplog: pytest.LogCaptureFixture) -> None:
    """Test if invalid auth attempts are logged."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            HOSTNAME,
            port=ssh_honeypot.port,
            username='invalid',
            password='invalid',
            timeout=5
        )
    except Exception:
        pass  # Expected to fail, but we check logs
    finally:
        client.close()

    assert "Authentication: invalid:invalid" in caplog.text


def test_concurrent_connections(ssh_honeypot):
    """Test 2 simultaneous connections with proper output handling."""
    clients: List[paramiko.SSHClient] = []

    try:
        for i in range(2):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                'localhost',
                port=ssh_honeypot.port,
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
        assert "root" in whoami_output or "Mocked LLM response\n\n" in whoami_output
        assert "file1.txt" in ls_output or "Mocked LLM response\n\n" in ls_output

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