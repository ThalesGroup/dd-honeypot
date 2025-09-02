import json

from base_honeypot import BaseHoneypot


class ProtocolDispatcher:
    """Load config from JSON and route sessions to appropriate handlers."""

    def __init__(self, config_path: str, backends: dict[str, "BaseHoneypot"]):
        self.backends = backends  # name → honeypot instance
        self.sessions = {}  # session_id → {"handler": BaseHoneypot}

        with open(config_path, "r") as f:
            self.config = json.load(f)

        self.handler_names = set()
        for honeypot_cfg in self.config.get("honeypots", []):
            self.handler_names.update(honeypot_cfg.get("handlers", []))

        # Validate that all configured handlers exist in backends
        missing_handlers = self.handler_names - set(backends.keys())
        if missing_handlers:
            print(
                f"Warning: Missing backend implementations for handlers: {missing_handlers}"
            )

    def _choose_handler(self, first_req: str) -> "BaseHoneypot":
        """Choose handler based on request content and config."""

        # Enhanced routing logic based on request patterns
        if "/phpmyadmin" in first_req.lower():
            return self.backends.get("php_my_admin", self.backends.get("default"))

        if "/login.htm" in first_req or "/admin" in first_req:
            return self.backends.get("boa_server_http", self.backends.get("default"))

        if first_req.startswith("SSH") or "ssh" in first_req.lower():
            return self.backends.get("mysql_ssh", self.backends.get("default"))

        # Try matching against handler names from config
        for honeypot_cfg in self.config.get("honeypots", []):
            for handler_name in honeypot_cfg.get("handlers", []):
                if handler_name in first_req or f"/{handler_name}" in first_req:
                    if handler_name in self.backends:
                        return self.backends[handler_name]

        # Default fallback
        return self.backends.get("default", next(iter(self.backends.values())))

    def route(self, session_id: str, first_req: str) -> "BaseHoneypot":
        """Return the handler that will own the whole session."""
        if session_id not in self.sessions:
            self.sessions[session_id] = {"handler": self._choose_handler(first_req)}
        return self.sessions[session_id]["handler"]

    def get_llm_config(self):
        """Get LLM configuration for use by handlers."""
        return self.config.get("llm", {})

    def get_honeypot_config(self, honeypot_type: str):
        """Get specific honeypot configuration by type."""
        for honeypot_cfg in self.config.get("honeypots", []):
            if honeypot_cfg.get("type") == honeypot_type:
                return honeypot_cfg
        return None
