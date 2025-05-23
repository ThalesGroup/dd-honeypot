import logging
import socket
import threading
import time
from pathlib import Path

import paramiko
from paramiko import Transport
from paramiko.ssh_exception import SSHException

from base_honeypot import BaseHoneypot
from infra.interfaces import HoneypotAction  # Define this interface


class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, action: HoneypotAction, honeypot: BaseHoneypot):
        self.username = None
        self.session = None
        self.action = action
        self.honeypot = honeypot

    def check_auth_password(self, username, password):
        logging.info(f"Authentication: {username}:{password}")
        self.username = username
        self.session = self.action.connect({"username": username, "password": password})
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel, command):
        command_str = command.decode().strip()
        logging.info(f"Command executed: {command_str}")

        # Log the command
        self.honeypot.log_data(self.session, {"method": "exec", "command": command_str})

        response = self.action.query(command_str, self.session)

        try:
            channel.send((response.strip() + "\n").encode())
            channel.send_exit_status(0)  # client know we finished
        except Exception as e:
            logging.error(f"Error sending response: {e}")
        finally:
            # Defer close a little to ensure client finishes reading
            def close_channel_later(chan, delay=0.5):
                time.sleep(delay)
                try:
                    chan.close()
                except EOFError:
                    logging.warning(
                        "Channel already closed before close_channel_later could run"
                    )

            import threading

            threading.Thread(
                target=close_channel_later, args=(channel,), daemon=True
            ).start()

        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.handle_shell, args=(channel,)).start()
        return True

    def handle_shell(self, channel):
        try:
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
                        channel.send("\b \b")
                    else:
                        buffer += char
                        channel.send(char)

                command = buffer.strip()
                if not command:
                    channel.send("\r\n")
                    continue

                logging.info(f"Shell command: {command}")
                self.honeypot.log_data(
                    self.session, {"method": "shell", "command": command}
                )

                if command.lower() in ["exit", "quit"]:
                    channel.send("\r\nConnection closed.\r\n")
                    break

                response = self.action.query(command, self.session)
                channel.send("\r\n" + response + "\r\n")

        except Exception as e:
            logging.error(f"Shell error: {e}")
        finally:
            channel.close()


class SSHHoneypot(BaseHoneypot):
    def __init__(self, port=0, action: HoneypotAction = None):
        super().__init__(port)
        self.action = action
        self.server_socket = None
        self.running = False
        self.host_key = self._load_host_key()

    def _load_host_key(self):
        import os
        from paramiko import RSAKey

        key_path = os.environ.get("HONEYPOT_HOST_KEY", "host.key")
        key_path = Path(key_path)

        if not key_path.exists():
            key_path.parent.mkdir(parents=True, exist_ok=True)
            RSAKey.generate(4096).write_private_key_file(str(key_path))

        return RSAKey(filename=str(key_path))

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", self.port))
        if self.port == 0:
            self.port = self.server_socket.getsockname()[1]
        self.server_socket.listen(100)
        self.running = True

        logging.info(f"SSH Honeypot running on port {self.port}")
        threading.Thread(target=self._listen, daemon=True).start()
        return self

    def _listen(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                client_socket.settimeout(10)
                threading.Thread(
                    target=self._handle_client, args=(client_socket, addr), daemon=True
                ).start()
            except Exception as e:
                if self.running:
                    logging.error(f"Accept error: {e}")

    def _handle_client(self, client_socket, addr):
        transport = None
        try:
            transport = Transport(client_socket)
            transport.local_version = "SSH-2.0-OpenSSH_8.9p1"
            transport.add_server_key(self.host_key)
            transport.start_server(server=SSHServerInterface(self.action, self))

            start_time = time.time()
            while transport.is_active() and (time.time() - start_time < 30):
                channel = transport.accept(1)
                if channel:
                    channel.event.wait()

        except (SSHException, Exception) as e:
            logging.error(f"SSH error: {e}")
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
