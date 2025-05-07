import json
import uuid
import paramiko
import socket
import threading
import logging
import os
import time

from paramiko import Transport, RSAKey
from paramiko.ssh_exception import SSHException

from pathlib import Path
from src.infra.data_handler import DataHandler
from src.llm_utils import invoke_llm

# ----------------- Logging Configuration -----------------
log_dir = Path(__file__).parent.parent / 'logs'
log_dir.mkdir(exist_ok=True)
log_file = log_dir / 'honeypot.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# ----------------- Session Tracking -----------------
class HoneypotSession:
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.info = {}

# ----------------- Server Interface -----------------
class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, data_handler):
        self.data_handler = data_handler
        self.username = None

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
        if response is None:
            response = "command not found\n"

        channel.send(response)
        channel.send_exit_status(0)
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.handle_shell, args=(channel,)).start()
        return True

    def lookup_command(self, command: str) -> str:
        return self.data_handler.get_data(command)

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

                response = self.lookup_command(command) or f"{command}: command not found"
                channel.send(response + "\r\n")

        except Exception as e:
            logging.error(f"Shell error: {e}")
        finally:
            channel.close()

# ----------------- Honeypot Core -----------------
class SSHHoneypot:
    def __init__(self, port: int = 0, data_handler=None):
        self.data_handler = data_handler
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
            transport.local_version = "SSH-2.0-OpenSSH_8.9p1"
            transport.add_server_key(self.host_key)

            # Use our custom interface
            transport.start_server(server=SSHServerInterface(data_handler=self.data_handler))

            # Keep alive for 30 seconds max
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

# ----------------- Entrypoint -----------------
if __name__ == "__main__":
    DATA_FILE = "honeypots/ssh/data.jsonl"
    SYSTEM_PROMPT = "You are a Linux terminal. Respond to shell commands accordingly."
    MODEL_ID = "anthropic.claude-instant-v1"

    data_handler = DataHandler(
        data_file=DATA_FILE,
        system_prompt=SYSTEM_PROMPT,
        model_id=MODEL_ID,
        invoke_fn=invoke_llm
    )

    honeypot = SSHHoneypot(port=2222, data_handler=data_handler).start()

    try:
        input("Press Enter to stop...\n")
    finally:
        honeypot.stop()