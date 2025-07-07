from typing import Dict
from base_honeypot import BaseHoneypot, HoneypotSession
from infra.interfaces import HoneypotAction


class SessionRouter:
    def __init__(self, honeypots: Dict[str, BaseHoneypot], default: str):
        self.honeypots = honeypots
        self.current = honeypots[default]

    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        response = self.current.action.query(query, session, **kwargs)

        # Check for switch signal in result
        if isinstance(response, dict) and "switch_to" in response:
            new_target = response["switch_to"]
            if new_target in self.honeypots:
                self.current = self.honeypots[new_target]
                response = response.get("output", f"Switched to {new_target}")
            else:
                response = f"Invalid honeypot target: {new_target}"
        elif isinstance(response, dict):
            response = response.get("output", "")

        return response

    def connect(self, session: HoneypotSession) -> HoneypotSession:
        return self.current.action.connect(session)
