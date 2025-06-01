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
