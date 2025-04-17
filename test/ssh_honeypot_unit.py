import pytest
import paramiko
import socket
import time
import logging
from src.ssh_honeypot import SSHHoneypot
from typing import Generator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def wait_for_ssh(port: int, timeout: int = 30) -> bool:
    """Wait until SSH service is fully responsive with better cleanup"""
    start = time.time()
    last_exception = None

    while time.time() - start < timeout:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                'localhost',
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
def honeypot():
    """Fixture with more robust startup/shutdown"""
    hp = SSHHoneypot(port=0)
    try:
        hp.start()
        assert wait_for_ssh(hp.port, timeout=10), "Honeypot failed to start"
        yield hp
    finally:
        hp.stop()
        time.sleep(1)  # Give more time for cleanup


def test_basic_command_execution(honeypot):
    """Test with more resilient command execution"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            'localhost',
            port=honeypot.port,
            username='test',
            password='test',
            timeout=10,
            banner_timeout=10,
            auth_timeout=10
        )

        # Use separate stdout/stderr channels
        transport = client.get_transport()
        channel = transport.open_session(timeout=10)
        channel.exec_command('test-command')

        # Read output with timeout protection
        output = b''
        start = time.time()
        while time.time() - start < 10:
            if channel.recv_ready():
                output += channel.recv(1024)
            if channel.exit_status_ready():
                break
            time.sleep(0.1)

        assert b'command not found' in output
        assert channel.recv_exit_status() == 1

    finally:
        client.close()


def test_interactive_shell(honeypot):
    """More robust interactive shell test"""
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
            auth_timeout=10
        )

        # Create shell with separate channel
        transport = client.get_transport()
        channel = transport.open_session(timeout=10)
        channel.get_pty()
        channel.invoke_shell()

        # Wait for prompt
        output = b''
        start = time.time()
        while time.time() - start < 10:
            if channel.recv_ready():
                output += channel.recv(1024)
                if b'$ ' in output:  # Look for shell prompt
                    break
            time.sleep(0.1)
        else:
            pytest.fail("Timeout waiting for shell prompt")

        # Send command
        channel.send('ls\n')

        # Get response
        output = b''
        start = time.time()
        while time.time() - start < 10:
            if channel.recv_ready():
                output += channel.recv(1024)
                if b'$ ' in output:  # Look for next prompt
                    break
            time.sleep(0.1)

        assert b'command not found' in output

        # Clean exit
        channel.send('exit\n')
        channel.shutdown_write()

        # Wait for closure
        start = time.time()
        while not channel.closed and time.time() - start < 5:
            time.sleep(0.1)

    finally:
        client.close()