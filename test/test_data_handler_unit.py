import os
import json
import pytest
from unittest.mock import patch
from src.infra.data_handler import DataHandler


@patch("src.infra.data_handler.invoke_llm", return_value="Mocked LLM response")
def test_llm_response_when_not_cached(mock_llm):
    data_file = os.path.join("/tmp", "ssh.jsonl")
    handler = DataHandler(data_file, "fake system prompt", "fake_model")

    user_input = "whoami"
    user_prompt = f"The user entered: {user_input}"
    response = handler.get_data(user_input)

    assert response == "Mocked LLM response"
    assert mock_llm.called


@patch("src.infra.data_handler.invoke_llm", return_value="ShouldNotBeCalled")
def test_returns_cached_response_first(mock_llm):
    data_file = os.path.join("/tmp", "ssh.jsonl")

    # Preload data manually
    with open(data_file, "w") as f:
        f.write(json.dumps({"command": "ls", "response": "file1.txt\n"}) + "\n")

    handler = DataHandler(data_file, "system", "model")
    response = handler.get_data("ls")

    assert response == "file1.txt\n"
    mock_llm.assert_not_called()


@patch("src.infra.data_handler.invoke_llm", return_value="Cached LLM response")
def test_memory_cache_is_used(mock_llm):
    data_file = os.path.join("/tmp", "ssh.jsonl")
    handler = DataHandler(data_file, "system", "model")

    cmd = "uptime"
    prompt = f"The user entered: {cmd}"

    # First call - triggers LLM
    response1 = handler.get_data(cmd)
    assert response1 == "Cached LLM response"
    assert mock_llm.call_count == 1

    # Second call - uses memory cache
    response2 = handler.get_data(cmd)
    assert response2 == "Cached LLM response"
    assert mock_llm.call_count == 1  # Should not call again

@patch("src.infra.data_handler.invoke_llm", return_value="Mocked LLM response for MySQL")
def test_mysql_llm_response_when_not_cached(mock_llm):
    data_file = os.path.join("/tmp", "mysql.jsonl")
    handler = DataHandler(data_file, "fake mysql prompt", "mysql_model")

    query = "SELECT * FROM users"
    user_prompt = f"The user ran: {query}"
    response = handler.get_data(query)

    assert response == "Mocked LLM response for MySQL"
    assert mock_llm.called


@patch("src.infra.data_handler.invoke_llm", return_value="ShouldNotBeCalled")
def test_mysql_returns_file_cache(mock_llm):
    data_file = os.path.join("/tmp", "mysql.jsonl")

    with open(data_file, "w") as f:
        f.write(json.dumps({"command": "SHOW TABLES", "response": "users\norders\n"}) + "\n")

    handler = DataHandler(data_file, "mysql sys", "mysql_model")
    response = handler.get_data("SHOW TABLES")

    assert response == "users\norders\n"
    mock_llm.assert_not_called()

@patch("src.infra.data_handler.invoke_llm", return_value="Mocked LLM response for HTTP")
def test_http_llm_response_when_not_cached(mock_llm):
    data_file = os.path.join("/tmp", "http.jsonl")
    handler = DataHandler(data_file, "fake http prompt", "http_model")

    http_request = "GET /admin?user=root"
    user_prompt = f"The user made: {http_request}"
    response = handler.get_data(http_request)

    assert response == "Mocked LLM response for HTTP"
    assert mock_llm.called


@patch("src.infra.data_handler.invoke_llm", return_value="ShouldNotBeCalled")
def test_http_returns_file_cache(mock_llm):
    data_file = os.path.join("/tmp", "http.jsonl")

    with open(data_file, "w") as f:
        f.write(json.dumps({"command": "GET /status", "response": '{"status":"ok"}'}) + "\n")

    handler = DataHandler(data_file, "http sys", "http_model")
    response = handler.get_data("GET /status")

    assert response == '{"status":"ok"}'
    mock_llm.assert_not_called()