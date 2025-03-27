from abc import ABC, abstractmethod


class BaseHoneypot(ABC):

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def stop(self):
        pass