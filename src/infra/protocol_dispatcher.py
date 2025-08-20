from base_honeypot import BaseHoneypot

class ProtocolDispatcher:
    """One-shot router – called ONLY on the very first packet of a session."""

    def __init__(self, backends: dict[str, "BaseHoneypot"]):
        self.backends = backends  # name → honeypot instance
        self.sessions = {}  # session_id → {"handler": BaseHoneypot}

    def _choose_handler(self, first_req: str) -> "BaseHoneypot":
        if first_req.startswith("/phpmyadmin"):
            return self.backends["php_my_admin"]
        if first_req.startswith("/login.htm"):
            return self.backends["boa_server_http"]
        if first_req.startswith("SSH"):
            return self.backends["mysql_ssh"]
        # default:
        return next(iter(self.backends.values()))

    def route(self, session_id: str, first_req: str) -> "BaseHoneypot":
        """Return the handler that will own the whole session."""
        if session_id not in self.sessions:
            self.sessions[session_id] = {"handler": self._choose_handler(first_req)}
        return self.sessions[session_id]["handler"]
