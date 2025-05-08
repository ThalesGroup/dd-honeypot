import time
import paramiko
from pathlib import Path
from src.infra.honeypot_wrapper import create_honeypot


def test_ssh_honeypot_with_llm_fallback(tmp_path: Path):
    # Setup config with temporary data file and mock model
    data_file = tmp_path / "data.jsonl"
    config = {
        "type": "ssh",
        "port": 0,
        "data_file": str(data_file),
        "system_prompt": "You are a Linux terminal emulator.",
        "model_id": "test-model"  # Will be used by mock later
    }

    # Patch the actual LLM to return predictable output
    def mock_invoke_llm(system_prompt, user_prompt, model_id):
        return "Mocked SSH response"

    # Monkey patch inside wrapper before creating honeypot
    import src.infra.honeypot_wrapper as wrapper
    wrapper.invoke_llm = mock_invoke_llm

    # Create honeypot using new wrapper
    honeypot = create_honeypot(config)
    honeypot.start()
    time.sleep(0.1)

    try:
        # Connect via SSH
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
        assert decoded_output == "Mocked SSH response"

    finally:
        honeypot.stop()