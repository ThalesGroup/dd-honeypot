import socket
import logging
from typing import Generator
import pytest
from base_honeypot import BaseHoneypot, HoneypotSession
from infra.interfaces import HoneypotAction
from redis_honeypot import RedisHoneypot

logger = logging.getLogger(__name__)


@pytest.fixture
def redis_honeypot() -> Generator[BaseHoneypot, None, None]:
    class MockRedisAction(HoneypotAction):
        def query(self, query: str, session: HoneypotSession, **kwargs) -> dict:
            # Fallback for PING if not handled by main logic (though it is now)
            return {"output": "+PONG\r\n"}

    honeypot = RedisHoneypot(
        action=MockRedisAction(), config={"name": "TestRedisHoneypot"}
    )
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


@pytest.fixture
def client_socket() -> Generator[socket.socket, None, None]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        yield s


def test_redis_ping(redis_honeypot, client_socket):
    client_socket.connect(("0.0.0.0", redis_honeypot.port))
    client_socket.sendall(b"PING\r\n")
    response = client_socket.recv(1024)
    assert response == b"+PONG\r\n"


def test_redis_auth(redis_honeypot, client_socket):
    client_socket.connect(("0.0.0.0", redis_honeypot.port))
    client_socket.sendall(b"AUTH supersecret\r\n")
    response = client_socket.recv(1024)
    assert response == b"+OK\r\n"


def test_redis_keys_del(redis_honeypot, client_socket):
    client_socket.connect(("0.0.0.0", redis_honeypot.port))
    # Set keys
    client_socket.sendall(b"SET k1 v1\r\n")
    client_socket.recv(1024)
    client_socket.sendall(b"SET k2 v2\r\n")
    client_socket.recv(1024)
    # List keys
    client_socket.sendall(b"KEYS *\r\n")
    response = client_socket.recv(4096)
    # Expecting RESP array of size 2
    assert b"*2\r\n" in response
    assert b"k1" in response
    assert b"k2" in response
    # Delete k1
    client_socket.sendall(b"DEL k1\r\n")
    response = client_socket.recv(1024)
    assert response == b":1\r\n"

    # Verify k1 is gone
    client_socket.sendall(b"GET k1\r\n")
    # Consume the fallback response (MockAction returns +PONG)
    client_socket.recv(1024)

    client_socket.sendall(b"KEYS *\r\n")
    response = client_socket.recv(4096)
    assert b"*1\r\n" in response
    assert b"k2" in response
    assert b"k1" not in response


def test_redis_select_isolation(redis_honeypot, client_socket):
    client_socket.connect(("0.0.0.0", redis_honeypot.port))
    # Set in DB 0
    client_socket.sendall(b"SET db0_key val\r\n")
    client_socket.recv(1024)
    # Switch to DB 1
    client_socket.sendall(b"SELECT 1\r\n")
    response = client_socket.recv(1024)
    assert response == b"+OK\r\n"
    # Verify key not visible in DB 1
    client_socket.sendall(b"KEYS *\r\n")
    response = client_socket.recv(4096)
    assert response == b"*0\r\n"

    # Set in DB 1
    client_socket.sendall(b"SET db1_key val\r\n")
    client_socket.recv(1024)
    # Switch back to DB 0
    client_socket.sendall(b"SELECT 0\r\n")
    client_socket.recv(1024)

    # Verify db0_key visible
    client_socket.sendall(b"KEYS *\r\n")
    response = client_socket.recv(4096)
    assert b"db0_key" in response
    assert b"db1_key" not in response


def test_redis_info(redis_honeypot, client_socket):
    client_socket.connect(("0.0.0.0", redis_honeypot.port))

    client_socket.sendall(b"INFO\r\n")
    response = client_socket.recv(4096)
    decoded = response.decode()
    assert "redis_version" in decoded
    assert "uptime_in_seconds" in decoded
