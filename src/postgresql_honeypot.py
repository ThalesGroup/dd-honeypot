import asyncio
import threading
import logging
import json

from buenavista.postgres import BuenaVistaServer, BVContext
from base_honeypot import BaseHoneypot
from infra.interfaces import HoneypotAction

logger = logging.getLogger(__name__)


class PostgresHoneypot(BaseHoneypot):
    def __init__(self, port=None, action: HoneypotAction = None, config=None):
        super().__init__(port, config)
        self._action = action
        self._thread = None
        self._server = None
        self.bound_port = None
        self._port_ready = threading.Event()

    def honeypot_type(self) -> str:
        return "postgres"

    def _create_handler(self):
        action = self._action
        log_data = self.log_data

        class Handler:
            def __init__(self, ctx: BVContext):
                self.ctx = ctx
                self._honeypot_session = None

            async def init(self):
                if action:
                    self._honeypot_session = action.connect(
                        {"client": self.ctx.params.get("user", "unknown")}
                    )

            async def handle_query(self, query: str):
                if log_data:
                    log_data(self._honeypot_session, {"query": query})

                try:
                    context = self._honeypot_session or {}
                    response = action.query(query, context)
                    parsed = json.loads(response)
                    if isinstance(parsed, list) and parsed:
                        columns = list(parsed[0].keys())
                        await self.ctx.send_row_description(
                            columns, ["text"] * len(columns)
                        )
                        for row in parsed:
                            await self.ctx.send_data_row(
                                [str(row.get(col, "")) for col in columns]
                            )
                        await self.ctx.send_command_complete("SELECT")
                        return
                except Exception as e:
                    logger.warning(f"LLM fallback failed: {e}")
                    logger.debug(f"Raw response: {locals().get('response', '')}")

                await self.ctx.send_row_description(["fake"], ["text"])
                await self.ctx.send_data_row(["This is a honeypot"])
                await self.ctx.send_command_complete("SELECT")

            async def handle(self):
                await self.init()
                while True:
                    try:
                        message = await self.ctx.recv_message()
                        if message.query:
                            await self.handle_query(message.query)
                    except Exception as e:
                        logger.warning(f"Connection closed or error: {e}")
                        break

        return Handler

    async def run_server(self):
        async def handle(ctx: BVContext):
            handler = self._create_handler()(ctx)
            await handler.handle()

        server = BuenaVistaServer(
            ("0.0.0.0", self.port), conn=self._action, handle_connection=handle
        )
        self._server = server
        logger.info(f"PostgreSQL honeypot running on port {self.port}")
        await server.serve_forever()

    def start(self):
        def _start():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            server = BuenaVistaServer(("0.0.0.0", self.port), conn=self._action)

            # 🔧 Store actual port and signal readiness
            self.bound_port = server.socket.getsockname()[1]
            self._port_ready.set()  # 🔧 Mark that bound_port is ready

            async def handle(ctx: BVContext):
                handler = self._create_handler()(ctx)
                await handler.handle()

            server.handle_connection = handle
            self._server = server

            logger.info(f"PostgreSQL honeypot running on port {self.bound_port}")
            loop.run_until_complete(server.serve_forever())

        self._thread = threading.Thread(target=_start, daemon=True)
        self._thread.start()

        # 🔧 Block until bound_port is ready
        if not self._port_ready.wait(timeout=5):
            raise RuntimeError("Timeout: PostgreSQL honeypot failed to bind port")

    def stop(self):
        if self._server:
            self._server.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        logger.info(f"Stopped PostgreSQL honeypot on port {self.bound_port}")
