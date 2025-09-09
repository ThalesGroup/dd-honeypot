import logging
import os
import select
import shlex
import socket
import threading
import time
from pathlib import Path

import paramiko
from paramiko import Transport
from paramiko.ssh_exception import SSHException

from base_honeypot import BaseHoneypot, HoneypotSession
from infra.interfaces import HoneypotAction
from infra.prompt_utils import render_prompt


class SuppressEOFErrorFilter(logging.Filter):
    def filter(self, record):
        return "EOFError" not in record.getMessage()


logging.getLogger("paramiko.transport").addFilter(SuppressEOFErrorFilter())

SSH_SESSIONS = {}


class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, action: HoneypotAction, honeypot: BaseHoneypot, config):
        self._action = action
        self.username = None
        self.session = None
        self.honeypot = honeypot
        self.config = config or {}

    @property
    def action(self):
        return (
            self._action
            if self._action is not None
            else getattr(self.honeypot, "action", None)
        )

    @action.setter
    def action(self, value):
        self._action = value

    def get_allowed_auths(self, username):
        # Explicitly advertise password auth
        return "password"  # paramiko expects a comma-separated list

    def check_auth_password(self, username, password):
        # Honeypot accepts any credentials; record them and (optionally) init a backend session
        logging.info("Authentication: %s:%s", username, password)
        self.username = username  # ensures prompt rendering can include the user
        if self.session is None:
            self.session = HoneypotSession()
        if self.action is not None:
            try:
                sess = self.action.connect({"username": username, "password": password})
                # prefer backend-provided session dict if applicable
                if isinstance(sess, dict):
                    self.session.update(sess)
            except Exception as e:
                logging.warning("Backend connect failed, continuing auth: %r", e)
        # Log login
        self.honeypot.log_login(
            self.session, {"username": username, "password": password}
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def handle_scp_upload(self, channel, command_str):
        try:
            channel.settimeout(10.0)
            logging.info(f"Handling SCP upload: {command_str}")

            # Step 1: Initial handshake
            channel.sendall(b"\x00")
            logging.info("Sent initial null byte to acknowledge SCP -t")

            # Step 2: Wait until header is ready to be read
            start_time = time.time()
            while True:
                rlist, _, _ = select.select([channel], [], [], 0.5)
                if rlist:
                    break
                if time.time() - start_time > 10:
                    raise TimeoutError("Timeout waiting for SCP header.")

            # Step 3: Read SCP header (e.g., C0644 1234 filename.txt\n)
            header = b""
            while not header.endswith(b"\n"):
                chunk = channel.recv(1)
                if not chunk:
                    logging.warning(
                        "SCP upload aborted: empty chunk while reading header"
                    )
                    return
                header += chunk
            logging.info(f"Received header: {header!r}")

            if not header.startswith(b"C"):
                logging.error("Invalid SCP header, expected 'C...'")
                return

            parts = header.strip().split(b" ")
            if len(parts) != 3:
                logging.error("Invalid SCP header format.")
                return

            mode = parts[0].decode()  # C0644
            size = int(parts[1])  # file size
            filename = parts[2].decode()

            logging.info(f"SCP Uploading file: {filename} ({size} bytes)")
            channel.sendall(b"\x00")  # Acknowledge file header

            # Step 4: Receive file content
            file_data = b""
            while len(file_data) < size:
                chunk = channel.recv(min(4096, size - len(file_data)))
                if not chunk:
                    logging.warning("Client closed before full file sent.")
                    return
                file_data += chunk

            # Step 5: Expect and check final null byte
            final_ack = channel.recv(1)
            if final_ack != b"\x00":
                logging.warning(f"Expected final ack null byte, got {final_ack!r}")

            # Step 6: Save the file
            upload_dir = self.config.get("upload_dir", "./uploaded_files")
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, os.path.basename(filename))
            with open(file_path, "wb") as f:
                f.write(file_data)
            logging.info(f"File {filename} saved to {file_path}")

            # Step 7: Final ACK to sender
            channel.sendall(b"\x00")

        except TimeoutError as te:
            logging.error(f"SCP upload timed out: {te}")
        except Exception as e:
            logging.error(f"Error handling SCP upload: {e}")
            try:
                channel.send(b"\x01")
            except:
                pass
        finally:
            try:
                channel.shutdown_write()
            except Exception:
                pass
            time.sleep(0.2)
            channel.close()

    def check_channel_exec_request(self, channel, command):
        command_str = command.decode().strip()
        logging.info(f"Command executed: {command_str}")

        try:
            parts = shlex.split(command_str)
        except ValueError:
            parts = []
        if parts and parts[0] == "scp" and "-t" in parts:
            logging.info("Detected SCP upload request.")
            self.handle_scp_upload(channel, command_str)
            return True

        try:
            self.honeypot.log_data(
                self.session, {"method": "exec", "command": command_str}
            )

            # Check if action is available
            if self.action is None:
                logging.error("No action available for command processing")
                channel.sendall(b"Command not available\n")
                channel.send_exit_status(1)
                channel.shutdown_write()
                return False

            result = self.action.query(command_str, self.session)
            output = result["output"] if isinstance(result, dict) else str(result)

            channel.sendall((output.strip() + "\n").encode())
            channel.send_exit_status(0)
            threading.Timer(0.1, lambda: channel.shutdown_write()).start()
            return True

        except Exception as e:
            logging.error(f"Error executing command: {e}")
            try:
                channel.send_exit_status(1)
                threading.Timer(0.1, lambda: channel.shutdown_write()).start()
            except:
                pass
            return False

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.handle_shell, args=(channel,)).start()
        return True

    def handle_shell(self, channel):
        try:
            cwd = self.session.get("cwd", "/")
            prompt_template = (
                self.config.get("prompt_template")
                or self.config.get("shell-prompt")
                or f"{self.username}@SSHServer:{cwd}$ "
            )

            prompt = render_prompt(prompt_template, self.session)

            while not channel.closed:
                buffer = ""
                channel.send(prompt)
                escape_seq = ""

                while True:
                    data = channel.recv(1)
                    if not data:
                        return

                    char = data.decode("utf-8", errors="ignore")

                    if char == "\x1b":
                        escape_seq = char
                        continue

                    if escape_seq:
                        escape_seq += char
                        if len(escape_seq) == 2 and char != "[":
                            channel.send(escape_seq)
                            escape_seq = ""
                        elif len(escape_seq) == 3:
                            # Ignore arrow keys: ↑↓←→
                            if escape_seq in ("\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D"):
                                pass  # Ignore silently
                            else:
                                channel.send(escape_seq)
                            escape_seq = ""
                        continue

                    if char in ("\r", "\n"):
                        break
                    elif char == "\x7f":  # Backspace
                        if buffer:
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

                if command.lower() in ["exit", "quit", "logout"]:
                    channel.send("\r\nConnection closed.\r\n")
                    break

                if self.action is None:
                    channel.send(b"\r\nCommand not available\r\n")
                    continue

                response = self.action.query(command, self.session)
                output = (
                    response["output"] if isinstance(response, dict) else str(response)
                )
                channel.send(("\r\n" + output + "\r\n").encode())

        except Exception as e:
            logging.error(f"Shell error: {e}")
        finally:
            channel.close()


class SSHHoneypot(BaseHoneypot):
    def __init__(self, port=0, action: HoneypotAction = None, config: dict = None):
        super().__init__(port, config)
        self.server_socket = None
        self.running = False
        self.session = {}
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
        logging.getLogger("paramiko.transport").setLevel(logging.WARNING)
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
            transport.handshake_timeout = 30
            transport.banner_timeout = 30
            transport.add_server_key(self.host_key)
            transport.start_server(
                server=SSHServerInterface(self.action, self, self.config)
            )

            start_time = time.time()
            while transport.is_active() and (time.time() - start_time < 60):
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
