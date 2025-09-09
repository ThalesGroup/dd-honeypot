import time
from pathlib import Path
from unittest.mock import patch, Mock

import paramiko
import pytest
from infra.honeypot_wrapper import create_honeypot


@pytest.mark.usefixtures("tmp_path")
def test_ssh_honeypot_with_llm_fallback(tmp_path: Path):
    data_file = tmp_path / "data.jsonl"

    with patch("infra.data_handler.invoke_llm", return_value="Mocked Response"):
        config = {
            "type": "ssh",
            "port": 0,
            "data_file": str(data_file),
            "system_prompt": "You are a Linux terminal emulator.",
            "model_id": "test-model",
        }

        mock_action = Mock()
        mock_action.query.return_value = "Mocked Response"
        mock_action.connect.return_value = {}

        honeypot = create_honeypot(config)
        honeypot.action = mock_action
        honeypot.start()
        time.sleep(0.1)

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                "localhost",
                port=honeypot.port,
                username="testuser",
                password="testpass",
            )

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
