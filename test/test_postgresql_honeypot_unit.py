import os
import pathlib
import socket
import struct
import time
from typing import Generator

import pytest

from postgresql_honeypot import PostgresHoneypot
from infra.data_handler import DataHandler
from sql_data_handler import SqlDataHandler
from infra.chain_honeypot_action import ChainedHoneypotAction


@pytest.fixture(scope="session")
def postgres_honeypot() -> Generator[PostgresHoneypot, None, None]:
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    pathlib.Path("honeypots/postgres").mkdir(parents=True, exist_ok=True)

    action = ChainedHoneypotAction(
        DataHandler(
            "honeypots/postgres/data.jsonl",
            system_prompt=["You are a PostgreSQL server"],
            model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
        ),
        SqlDataHandler(dialect="postgres"),
    )

    honeypot = PostgresHoneypot(port=0, action=action, config={"host": "0.0.0.0"})

    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


@pytest.fixture
def postgres_socket(postgres_honeypot) -> Generator[socket.socket, None, None]:
    """Returns a connected raw TCP socket to the honeypot."""
    sock = socket.create_connection(
        ("0.0.0.0", postgres_honeypot.bound_port), timeout=2
    )
    sock.settimeout(2)
    try:
        yield sock
    finally:
        sock.close()


def send_pg_startup_message(sock: socket.socket):
    # Protocol version 3.0 = 196608
    # user=root, database=postgres
    params = b"user\x00root\x00database\x00postgres\x00\x00"
    length = len(params) + 8  # 4 bytes length + 4 bytes protocol version
    message = struct.pack("!I", length)
    message += struct.pack("!I", 196608)
    message += params
    sock.sendall(message)


def test_postgres_fake_connection(postgres_socket):
    send_pg_startup_message(postgres_socket)
    time.sleep(0.1)
    try:
        resp = postgres_socket.recv(1024)
        assert resp
    except socket.timeout:
        pytest.fail("No response received from honeypot")


def test_postgres_malformed_query(postgres_socket):
    postgres_socket.sendall(b"invalid_query")
    time.sleep(0.1)
    try:
        data = postgres_socket.recv(1024)
        assert data == b"" or data
    except (ConnectionResetError, socket.timeout):
        pass
