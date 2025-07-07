from base_honeypot import HoneypotSession
from infra.interfaces import HoneypotAction


class ChainedHoneypotAction(HoneypotAction):
    def __init__(self, inner_action, outer_action):
        super().__init__()
        self._inner_action = inner_action
        self._outer_action = outer_action

    def connect(self, auth_info: dict) -> HoneypotSession:
        session = self._outer_action.connect(auth_info)
        if not session:
            session = self._inner_action.connect(auth_info)
        return session

    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        result = self._outer_action.query(query, session, **kwargs)
        if not result:
            result = self._inner_action.query(query, session, **kwargs)
        return result

    def request(self, info: dict, session: HoneypotSession, **kwargs) -> str:
        result = self._outer_action.request(info, session, **kwargs)
        if not result:
            result = self._inner_action.request(info, session, **kwargs)
        return result


class MultiHoneypotAction(HoneypotAction):
    def __init__(self, honeypots: dict[str, HoneypotAction], default: str):
        self.honeypots = honeypots
        self.default = default

    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        # Initialize session.active_honeypot if missing
        if not hasattr(session, "active_honeypot") or session.active_honeypot is None:
            session.active_honeypot = self.default

        current_name = session.active_honeypot
        current_handler = self.honeypots[current_name]

        response = current_handler.query(query, session=session, **kwargs)

        # Check if a honeypot switch is required
        if isinstance(response, dict) and "switch_to" in response:
            new_name = response["switch_to"]
            if new_name in self.honeypots:
                session.active_honeypot = new_name
            else:
                raise ValueError(f"Invalid honeypot name in switch_to: {new_name}")

        return response
