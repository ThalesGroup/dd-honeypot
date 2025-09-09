import logging
from pathlib import Path
from infra.honeypot_wrapper import create_honeypot

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    config = {
        "type": "ssh",
        "port": 2222,
        "data_file": str(
            Path(__file__).parent.parent
            / "test"
            / "honeypots"
            / "alpine"
            / "data.jsonl"
        ),
        "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "system_prompt": "You are a Linux terminal emulator. Respond with only command outputs.",
    }

    honeypot = create_honeypot(config)
    honeypot.start()

    try:
        input("SSH Honeypot is running. Press Enter to stop...\n")
    finally:
        honeypot.stop()
