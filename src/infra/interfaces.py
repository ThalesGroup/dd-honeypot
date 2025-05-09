from abc import ABC, abstractmethod
from src.base_honeypot import HoneypotSession

class HoneypotAction(ABC):
    @abstractmethod
    def connect(self, auth_info: dict) -> HoneypotSession:
        pass

    @abstractmethod
    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        pass