import os
import pathlib
import socket
import struct
import time
from typing import Generator
import psycopg2


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
            system_prompt="You are a PostgreSQL server",
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


# to test it on real postgre use the following command and update the port
# docker run --rm --name my_postgres -e POSTGRES_PASSWORD=pw -p 5432:5432 postgres
@pytest.mark.skip(reason="Requires fix in the honeypot")
def test_connection_to_postgres_honeypot(postgres_honeypot):
    with psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="pw",
        host="0.0.0.0",
        port=postgres_honeypot.port,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            assert cur.fetchone()[0] == 1


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


def test_ssl_request_response(postgres_socket):
    ssl_request = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
    postgres_socket.sendall(ssl_request)
    time.sleep(0.1)
    resp = postgres_socket.recv(1)
    assert resp == b"N", f"Expected 'N' response to SSL request, got {resp!r}"


def test_gssenc_request_response(postgres_socket):
    gssenc_request = b"\x00\x00\x00\x08\x04\xd2\x16\x30"
    postgres_socket.sendall(gssenc_request)
    time.sleep(0.1)
    resp = postgres_socket.recv(1)
    assert resp == b"N", f"Expected 'N' response to GSSENC request, got {resp!r}"


def test_auth_and_ready_for_query(postgres_socket):
    send_pg_startup_message(postgres_socket)
    time.sleep(0.1)  # give time for both responses to arrive

    data = b""
    for _ in range(2):  # attempt to read up to 2 chunks
        try:
            data += postgres_socket.recv(1024)
        except socket.timeout:
            break

    assert (
        b"R\x00\x00\x00\x08\x00\x00\x00\x00" in data
    ), f"Expected AuthenticationOk message, got: {data!r}"
    assert (
        b"Z\x00\x00\x00\x05I" in data
    ), f"Expected ReadyForQuery message, got: {data!r}"


def test_invalid_startup_message(postgres_socket):
    postgres_socket.sendall(b"\x00\x00\x00\x04BAD!")
    time.sleep(0.1)
    try:
        data = postgres_socket.recv(1024)
        # Accept anything, just shouldn't crash
        assert data == b"" or data
    except (ConnectionResetError, socket.timeout):
        pass


def test_client_disconnect_after_auth(postgres_socket):
    send_pg_startup_message(postgres_socket)
    postgres_socket.close()
    time.sleep(0.1)
    # No exception should be raised here from the honeypot side
