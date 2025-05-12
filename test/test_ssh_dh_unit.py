import time
from unittest.mock import patch

import paramiko
from pathlib import Path
from src.infra.honeypot_wrapper import create_honeypot
from src.infra.data_handler import DataHandler

@patch("src.infra.data_handler.invoke_llm", return_value="Mocked Response")
def test_ssh_honeypot_with_llm_fallback(tmp_path: Path):
    # Temporary file for command caching
    data_file = tmp_path / "data.jsonl"

    # Mock function to replace real LLM call
    def mock_invoke_llm(system_prompt, user_prompt, model_id):
        return "Mocked SSH response"

    # Create a DataHandler with mock LLM
    action = DataHandler(
        data_file=str(data_file),
        system_prompt="You are a Linux terminal emulator.",
        model_id="test-model",
    )

    # Use manual config and injection
    config = {
        "type": "ssh",
        "port": 0,
        "data_file": str(data_file),
        "system_prompt": "You are a Linux terminal emulator.",
        "model_id": "test-model"
    }

    # Create honeypot with injected action
    honeypot = create_honeypot(config)
    honeypot.start()
    time.sleep(0.1)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect("localhost", port=honeypot.port, username="testuser", password="testpass")

        chan = client.get_transport().open_session()
        chan.exec_command("definitely-unseen-command-xyz")

        output = b""
        start_time = time.time()
        while time.time() - start_time < 5:
            if chan.recv_ready():
                output += chan.recv(4096)
            if chan.exit_status_ready():
                break
            time.sleep(0.1)

        decoded_output = output.decode().strip()
        assert decoded_output == "Mocked Response"

    finally:
        honeypot.stop()