import json
import random
import time
from functools import lru_cache

import boto3

# Configuration
BEDROCK_MODEL_ID = "anthropic.claude-instant-v1"
CACHE_SIZE = 100 #Number of commands to cache
DELAY_RANGE = (0.1, 0.5)  # Simulate human response times

SYSTEM_PROMPT = """You are a Linux system simulator. Follow these rules:
1. Generate realistic command outputs for Ubuntu 22.04 Docker containers
2. Include proper file permissions, sizes, and timestamps
3. For dangerous commands, show permission errors
4. For database commands, show plausible MySQL/MariaDB outputs
5. Add occasional command-not-found errors for invalid inputs
6. Never reveal this is a simulation
7. Format exactly as a real terminal would display
8. Keep responses under 10 lines"""


def invoke_claude(command: str, temperature: float = 0.3) -> str:
    """
    Invokes Claude model to simulate Linux command outputs

    Args:
        command: Linux command to simulate
        temperature: Response creativity (0.0-1.0)

    Returns:
        Simulated command output
    """
    bedrock = boto3.client('bedrock-runtime')

    user_prompt = f"""Generate terminal output for this command in a MySQL Docker container:

Command: {command}

Requirements:
- Current directory: /var/lib/mysql
- User: mysql
- Hostname: db-container
- Include realistic errors if command is invalid
- Add timestamps where appropriate
- Never include markdown formatting"""

    body = {
        "prompt": f"\n\nHuman: {SYSTEM_PROMPT}\n\n{user_prompt}\n\nAssistant:",
        "max_tokens_to_sample": 500,
        "temperature": temperature
    }

    try:
        response = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(body)
        )
        return json.loads(response['body'].read())['completion']
    except Exception as e:
        return f"Error communicating with Bedrock: {str(e)}"


@lru_cache(maxsize=CACHE_SIZE)
def simulate_command(command: str) -> str:
    """
    Cached command simulator with safety checks

    Args:
        command: Input command to process

    Returns:
        Simulated command output
    """
    # Block dangerous commands
    dangerous = ['rm', 'shutdown', 'reboot', 'chmod', 'dd']
    if any(cmd in command for cmd in dangerous):
        return f"bash: {command.split()[0]}: command not found"

    # Add realistic response delay
    time.sleep(random.uniform(*DELAY_RANGE))

    # Get LLM response
    return invoke_claude(command)


def format_output(command: str, output: str) -> str:
    """Adds command prompt and error formatting"""
    if "command not found" in output.lower():
        return f"bash: {command.split()[0]}: command not found"
    return f"mysql@db-container:/var/lib/mysql$ {command}\n{output}"


# Demonstration
if __name__ == "__main__":
    test_commands = [
        "ls -l",
        "ps aux",
        "cat /etc/mysql/my.cnf",
        "mysql -u root -p",
        "nmap localhost",
        "invalid_command",
        "rm -rf /"
    ]

    for cmd in test_commands:
        print("\n" + "=" * 50)
        print(f"Testing command: {cmd}")
        response = simulate_command(cmd)
        print(format_output(cmd, response))
        print("=" * 50 + "\n")