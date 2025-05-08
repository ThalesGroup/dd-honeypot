from src.infra.honeypot_wrapper import create_honeypot

if __name__ == "__main__":
    config = {
        "type": "ssh",
        "port": 2222,
        "data_file": "../test/honeypots/ssh/data.jsonl",
        "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "system_prompt": "You are a Linux terminal emulator. Respond with only command outputs, no extra text."
    }

    honeypot = create_honeypot(config)
    honeypot.start()
    try:
        input("Press Enter to stop...\n")
    finally:
        honeypot.stop()