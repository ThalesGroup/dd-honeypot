from abc import ABC

from base_honeypot import HoneypotSession


class HoneypotAction(ABC):

    def connect(self, auth_info: dict) -> HoneypotSession:
        """
        authenticate to the honeypot
        :param auth_info: authentication information, can be username and password, or other information used
        for authentication
        :return: True if authentication is successful, False otherwise
        """
        return HoneypotSession()

    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        """
        execute a query on the honeypot, for honeypots which support queries
        :param query:  to execute
        :param session: honeypot session context
        :return: result of the query
        """
        raise NotImplementedError()

    def request(self, info: dict, session: HoneypotSession, **kwargs) -> str:
        """
        execute a request on the honeypot. Request can be for example an HTTP request, or a command to execute
        :param info: request information
        :param session: honeypot session context
        :return: response of the request
        """
        raise NotImplementedError()
