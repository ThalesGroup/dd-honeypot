from typing import Dict, Any
from base_honeypot import BaseHoneypot 
from infra.interfaces import HoneypotSession


class Dispatcher:
    def __init__(self, honeypot_configs):
        self.honeypots = self._load_honeypots(honeypot_configs)
        self.sessions = {}  # session_id: session_obj

    def route(self, session_id, request):
        session = self.sessions.setdefault(session_id, self._init_session())
        current_honeypot = self.honeypots[session["mode"]]
        response = current_honeypot.handle(request, session)

        # Handle protocol switch
        if isinstance(response, dict) and "switch_to" in response:
            new_mode = response["switch_to"]
            session["mode"] = new_mode
            if "switch_back" in response:
                session["switch_back_command"] = response["switch_back"]
            session["previous_mode"] = current_honeypot.name
            # Optionally update prompt, etc.

        # Handle switch-back (e.g., exit command in MySQL)
        if (
            "switch_back_command" in session
            and request == session["switch_back_command"]
        ):
            session["mode"] = session.get("previous_mode", "ssh")
            # Optionally update prompt, etc.

        return response
