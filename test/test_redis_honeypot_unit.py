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
            cmd_parts = query.split()
            cmd = cmd_parts[0].upper()
            if cmd == "PING":
                return {"output": "+PONG\r\n"}
            elif cmd == "SET":
                return {"output": "+OK\r\n"}
            elif cmd == "GET":
                return {"output": "$3\r\nbar\r\n"}
            return {"output": "-ERR unknown command\r\n"}

    honeypot = RedisHoneypot(
        action=MockRedisAction(), config={"name": "TestRedisHoneypot"}
    )
    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()

def test_redis_ping(redis_honeypot):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.settimeout(3)
        client_socket.connect(("0.0.0.0", redis_honeypot.port))
        
        client_socket.sendall(b"PING\r\n")
        response = client_socket.recv(1024)
        assert response == b"+PONG\r\n"

def test_redis_set_get(redis_honeypot):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.settimeout(3)
        client_socket.connect(("0.0.0.0", redis_honeypot.port))
        
        client_socket.sendall(b"SET foo bar\r\n")
        response = client_socket.recv(1024)
        assert response == b"+OK\r\n"
        
        client_socket.sendall(b"GET foo\r\n")
        response = client_socket.recv(1024)
        assert response == b"$3\r\nbar\r\n"

def test_redis_inline_newline(redis_honeypot):
    """Test that the honeypot handles \n only (lenient parsing)"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.settimeout(3)
        client_socket.connect(("0.0.0.0", redis_honeypot.port))
        
        client_socket.sendall(b"PING\n")
        response = client_socket.recv(1024)
        assert response == b"+PONG\r\n"

def test_redis_stateful_set_get(redis_honeypot):
    """Test that the honeypot remembers values set in the session"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.settimeout(3)
        client_socket.connect(("0.0.0.0", redis_honeypot.port))
        
        # Set a dynamic value
        client_socket.sendall(b"SET my_dynamic_key dynamic_value\r\n")
        response = client_socket.recv(1024)
        assert response == b"+OK\r\n"
        
        # Get it back
        client_socket.sendall(b"GET my_dynamic_key\r\n")
        response = client_socket.recv(1024)
        # Expecting bulk string response
        expected = b"$13\r\ndynamic_value\r\n"
        assert response == expected
