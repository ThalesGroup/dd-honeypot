import pathlib
import socket
import struct
import time
import os
import pytest
from typing import Generator

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
        SqlDataHandler(dialect="postgresql"),
    )

    honeypot = PostgresHoneypot()
    honeypot.action = action

    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


@pytest.fixture
def postgres_cnn(postgres_honeypot) -> Generator[socket.socket, None, None]:
    host = "127.0.0.1"
    port = postgres_honeypot.bound_port
    with socket.create_connection((host, port), timeout=2) as sock:
        yield sock


def send_pg_startup_message(sock):
    params = b"user\x00postgres\x00database\x00postgres\x00\x00"
    length = len(params) + 4 + 4
    message = struct.pack("!I", length)
    message += struct.pack("!I", 196608)
    message += params
    sock.sendall(message)


def test_postgres_fake_connection(postgres_cnn):
    send_pg_startup_message(postgres_cnn)
    time.sleep(0.1)
    resp = postgres_cnn.recv(1024)
    assert resp


def test_postgres_malformed_query(postgres_cnn):
    postgres_cnn.sendall(b"garbage data")
    time.sleep(0.1)
    try:
        data = postgres_cnn.recv(1024)
        assert data == b"" or data
    except ConnectionResetError:
        pass
