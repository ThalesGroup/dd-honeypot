import time
import paramiko
from pathlib import Path
from src.infra.data_handler import DataHandler
from src.ssh_honeypot import SSHHoneypot

def test_ssh_honeypot_with_data_handler(tmp_path: Path):
    test_config = {
        "system_prompt": "You are a Linux terminal emulator.",
        "model_id": "test-model",
        "port": 0
    }

    # Step 1: create temp data file
    data_file = tmp_path / "data.jsonl"
    data_file.touch()

    # Step 2: define mock LLM function
    def mock_invoke_fn(query, system_prompt, model_id):
        return "Mocked SSH response"

    # Step 3: initialize DataHandler with mock
    data_handler = DataHandler(
        data_file=str(data_file),
        system_prompt=test_config["system_prompt"],
        model_id=test_config["model_id"],
        invoke_fn=mock_invoke_fn
    )

    honeypot = SSHHoneypot(port=test_config["port"], data_handler=data_handler)
    honeypot.start()
    time.sleep(0.1)

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

    honeypot.stop()
