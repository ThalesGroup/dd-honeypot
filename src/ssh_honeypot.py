import json
import uuid

import paramiko
import socket
import threading
import logging
import os

import time
from paramiko import Transport, ServerInterface, RSAKey
from paramiko.ssh_exception import SSHException

from llm_utils import invoke_llm

from pathlib import Path

# Configure logging with dynamic path handling
log_dir = Path(__file__).parent.parent / 'logs'
log_dir.mkdir(exist_ok=True)  # Create directory if it doesn't exist
log_file = log_dir / 'honeypot.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)


class HoneypotSession:
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.info = {}


class SSHHoneypot:
    def __init__(self, port: int = 0):
        self.port = port
        self.server_socket = None
        self.running = False
        self.host_key = self._load_host_key()
        self.threads = []

    def _load_host_key(self):
        key_path = "host.key"
        if not os.path.exists(key_path):
            RSAKey.generate(4096).write_private_key_file(key_path)
        return RSAKey(filename=key_path)

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        if self.port == 0:
            self.port = self.server_socket.getsockname()[1]
        self.server_socket.listen(100)
        self.running = True

        logging.info(f"SSH Honeypot running on port {self.port}")
        main_thread = threading.Thread(target=self._listen, daemon=True)
        main_thread.start()
        return self

    def _listen(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                client_socket.settimeout(10)
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.running:
                    logging.error(f"Accept error: {e}")

    def _handle_client(self, client_socket, addr):
        transport = None
        try:
            transport = Transport(client_socket)
            transport.local_version = "SSH-2.0-OpenSSH_8.9p1"  # Set server version
            transport.add_server_key(self.host_key)

            # Start SSH server with explicit banner handling
            transport.start_server(server=SSHServerInterface())

            # Maintain connection for 30 seconds
            start_time = time.time()
            while transport.is_active() and (time.time() - start_time < 30):
                channel = transport.accept(1)
                if channel:
                    channel.event.wait()

        except SSHException as e:
            logging.error(f"SSH error: {e}")
        except Exception as e:
            logging.error(f"Connection error: {e}")
        finally:
            if transport:
                transport.close()

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        logging.info("SSH Honeypot stopped")


class SSHServerInterface(ServerInterface):
    def __init__(self):
        self.auth_method = None
        self.username = None
        self.command_data = []

        self.data_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "honeypots", "ssh", "data.jsonl")
        )
        self.model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"
        self.system_prompt = (
            "You are a Linux terminal emulator. Respond with only command outputs, no extra text."
        )

        if os.path.exists(self.data_file):
            with open(self.data_file, "r") as f:
                for line in f:
                    if line.strip():
                        self.command_data.append(json.loads(line))


    def check_auth_password(self, username, password):
        logging.info(f'Authentication: {username}:{password}')
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        command_str = command.decode().strip()
        logging.info(f"Command executed: {command_str}")
        response = self.lookup_command(command_str)
        channel.send(response + "\n")
        channel.send_exit_status(0)
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.handle_shell, args=(channel,)).start()
        return True

    def lookup_command(self, command: str) -> str:
        for entry in self.command_data:
            if entry["command"] == command:
                return entry["response"]

        # Not found, use LLM
        logging.info(f"LLM fallback for command: {command}")
        user_prompt = f"The user entered: {command}"
        response = invoke_llm(self.system_prompt, user_prompt, self.model_id)
        self.command_data.append({"command": command, "response": response})
        self.save_command_data()
        return response

    def save_command_data(self):
        with open(self.data_file, "w") as f:
            for entry in self.command_data:
                f.write(json.dumps(entry) + "\n")

    def handle_shell(self, channel):
        try:
            channel.send("Welcome to SSH Server (Type 'help' for available commands)\r\n")
            prompt = f"{self.username}@honeypot:~$ "

            while not channel.closed:
                buffer = ""
                channel.send(prompt)
                while True:
                    data = channel.recv(1)
                    if not data:
                        return
                    char = data.decode("utf-8", errors="ignore")
                    if char in ("\r", "\n"):
                        break
                    elif char == "\x7f":
                        buffer = buffer[:-1]
                    else:
                        buffer += char

                command = buffer.strip()
                if not command:
                    continue

                logging.info(f"Shell command: {command}")

                if command.lower() in ['exit', 'quit']:
                    channel.send("Connection closed. Goodbye!!\r\n")
                    break

                response = self.lookup_command(command)
                channel.send(response + "\r\n")

        except Exception as e:
            logging.error(f"Shell error: {e}")
        finally:
            channel.close()

if __name__ == "__main__":
    honeypot = SSHHoneypot(port=2222).start()
    try:
        input("Press Enter to stop...\n")
    finally:
        honeypot.stop()