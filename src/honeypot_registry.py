from typing import List

from base_honeypot import BaseHoneypot


class HoneypotRegistry:
    def __init__(self):
        self._registry: List[BaseHoneypot] = []

    def register_honeypot(self, h: BaseHoneypot):
        self._registry.append(h)

    def register_honeypots(self, honeypots: List[BaseHoneypot]):
        for h in honeypots:
            self.register_honeypot(h)

    def get_honeypot(self, name) -> BaseHoneypot:
        for h in self._registry:
            if h.name == name:
                return h
        raise KeyError(name)

    def reset_honeypots(self):
        self._registry = []


_honeypot_registry_instance: HoneypotRegistry = HoneypotRegistry()


def get_honeypot_registry() -> HoneypotRegistry:
    return _honeypot_registry_instance
