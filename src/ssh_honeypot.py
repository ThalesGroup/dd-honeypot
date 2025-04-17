import uuid

import paramiko
import socket
import threading
import logging
import os
import time
from paramiko import Transport, ServerInterface, RSAKey
from paramiko.ssh_exception import SSHException

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('honeypot.log'),
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
        # Command responses dictionary
        self.command_responses = {
            'ls': "file1.txt  file2.log  secret_data\n",
            'whoami': "root\n",
            'id': "uid=0(root) gid=0(root) groups=0(root)\n",
            'uname -a': "Linux honeypot 5.15.0-76-generic #83-Ubuntu SMP Thu Jun 15 19:16:32 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n",
            'ifconfig': "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        ether 00:0c:29:ab:cd:ef  txqueuelen 1000  (Ethernet)\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n        loop  txqueuelen 1000  (Local Loopback)\n",
            'help': "Available commands: ls, whoami, id, uname -a, ifconfig, help\n"
        }

    def check_auth_password(self, username, password):
        logging.info(f'Authentication: {username}:{password}')
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        command_str = command.decode().strip()
        logging.info(f"Command executed: {command_str}")

        # Check if we have a hardcoded response
        if command_str in self.command_responses:
            channel.send(self.command_responses[command_str])
            channel.send_exit_status(0)  # Success exit code
        else:
            channel.send(f"{command_str}: command not found\n")
            channel.send_exit_status(1)  # Error exit code
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.handle_shell, args=(channel,)).start()
        return True

    def handle_shell(self, channel):
        try:
            channel.send("Welcome to SSH Server (Type 'help' for available commands)\r\n")
            prompt = f"{self.username}@honeypot:~$ "

            while not channel.closed:
                channel.send(prompt)
                data = channel.recv(1024)
                if not data:
                    break

                command = data.decode().strip()
                if command.lower() in ['exit', 'quit']:
                    channel.send("Connection closed\r\n")
                    channel.close()
                    break

                logging.info(f"Shell command: {command}")

                # Check for hardcoded response
                if command in self.command_responses:
                    channel.send(self.command_responses[command] + "\r\n")
                elif command.lower() == 'help':
                    channel.send("Available commands: " + ", ".join(self.command_responses.keys()) + "\r\n")
                else:
                    channel.send(f"{command}: command not found\r\n")

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