import asyncio
import logging
import threading
from typing import Optional

import telnetlib3


from base_honeypot import BaseHoneypot
from honeypot_utils import wait_for_port
from infra.interfaces import HoneypotAction

logger = logging.getLogger(__name__)


class TelnetHoneypot(BaseHoneypot):
    def __init__(
        self,
        port: int = None,
        action: HoneypotAction = None,
        config: dict = None,
    ):
        super().__init__(port, config)
        self._action = action
        self._thread = None

    def honeypot_type(self) -> str:
        return "telnet"

    @staticmethod
    async def read_line(reader, writer, echo: bool) -> Optional[str]:
        word = ""
        while True:
            char = await reader.read(1)
            if not char:
                return None
            if char in ("\r", "\n"):
                return word
            if char in ("\x08", "\x7f"):  # Backspace or DEL
                if word:
                    word = word[:-1]
                    writer.write("\b \b")
                    await writer.drain()
            elif char.isprintable():
                if echo:
                    writer.write(char)
                else:
                    writer.write("*")
                word += char

    async def shell(self, reader, writer):
        username, password = None, None
        if "telnet" in self.config:
            telnet_conf = self.config["telnet"]
            if "banner" in telnet_conf:
                writer.write(f"{telnet_conf['banner']}\r\n")
            if "login-prompt" in telnet_conf:
                writer.write(f"\r\n{telnet_conf['login-prompt']}")
                username = await self.read_line(reader, writer, True)
            if "password-prompt" in telnet_conf:
                writer.write(f"\r\n{telnet_conf['password-prompt']}")
                password = await self.read_line(reader, writer, False)
            if "post-login-message" in telnet_conf:
                writer.write(f"\r\n{telnet_conf['post-login-message']}\r\n")

        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else None
        login_data = {
            "client_ip": client_ip,
            "username": username.strip() if username else None,
            "password": password.strip() if password else None,
        }
        session = self._action.connect(login_data)
        self.log_login(session, login_data)
        shell_prompt = self.config.get("telnet", {}).get("shell-prompt", "# ")
        writer.write(f"\r\n{shell_prompt}")
        line = await self.read_line(reader, writer, True)
        while line is not None:
            self.log_data(
                session,
                {"command": line},
            )
            if line in ["exit", "quit", "logout"]:
                writer.write("\r\nGoodbye!\r\n")
                break
            else:
                response = self._action.query(line, session)
                writer.write(response.replace("\n", "\r\n"))
                writer.write(f"\r\n{shell_prompt}")
                line = await self.read_line(reader, writer, True)
        writer.close()

    async def run_server(self):
        logger.info(f"Telnet Honeypot started. Port: {self.port}")
        server = await telnetlib3.create_server(
            host="0.0.0.0", port=self.port, shell=self.shell, encoding="utf8"
        )
        await server.serve_forever()

    def start(self):
        def _start_asyncio_server():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            task = loop.create_task(self.run_server())
            try:
                loop.run_until_complete(task)
            except asyncio.CancelledError:
                pass
            finally:
                loop.close()

        thread = threading.Thread(target=_start_asyncio_server, daemon=True)
        thread.start()
        wait_for_port(self.port)

    def stop(self):
        if self._thread:
            self._thread.join(timeout=1)
