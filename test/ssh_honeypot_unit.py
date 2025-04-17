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
def honeypot() -> Generator[SSHHoneypot, None, None]:
    """Fixture with proper resource cleanup"""
    hp = SSHHoneypot(port=0)
    try:
        hp.start()
        assert wait_for_ssh(hp.port), "Honeypot failed to become responsive"
        yield hp
    finally:
        hp.stop()
        time.sleep(0.5)  # Allow socket cleanup


def test_basic_command_execution(honeypot: SSHHoneypot) -> None:
    """Test with explicit timeouts and resource cleanup"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect with strict timeouts
        client.connect(
            'localhost',
            port=honeypot.port,
            username='test',
            password='test',
            timeout=5,
            banner_timeout=5,
            auth_timeout=5
        )

        # Test command execution with timeout
        stdin, stdout, stderr = client.exec_command('test-command', timeout=5)
        output = stdout.read().decode('utf-8', errors='ignore')
        exit_status = stdout.channel.recv_exit_status()

        assert 'command not found' in output
        assert exit_status == 1

    finally:
        client.close()


def test_interactive_shell(honeypot: SSHHoneypot) -> None:
    """Test interactive shell with proper cleanup"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            'localhost',
            port=honeypot.port,
            username='user',
            password='pass',
            timeout=5,
            banner_timeout=5,
            auth_timeout=5
        )

        channel = client.invoke_shell()
        channel.settimeout(5)

        try:
            # Wait for prompt with timeout
            start = time.time()
            output = b''
            while time.time() - start < 5:
                if channel.recv_ready():
                    output += channel.recv(1024)
                    if b'$ ' in output:
                        break
                time.sleep(0.1)
            else:
                pytest.fail("Timeout waiting for shell prompt")

            # Test command
            channel.send('ls\n')

            # Get response with timeout
            output = b''
            start = time.time()
            while time.time() - start < 5:
                if channel.recv_ready():
                    output += channel.recv(1024)
                    if b'$ ' in output:  # Look for prompt return
                        break
                time.sleep(0.1)
            else:
                pytest.fail("Timeout waiting for command response")

            assert b'command not found' in output

            # Clean exit
            channel.send('exit\n')
            channel.shutdown_write()

            # Wait for clean channel closure
            start = time.time()
            while not channel.closed and time.time() - start < 5:
                time.sleep(0.1)

        finally:
            channel.close()

    finally:
        client.close()