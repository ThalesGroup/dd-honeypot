from time import sleep

import pytest

from base_honeypot import BaseHoneypot
from honeypot_utils import allocate_port
from llm_utils import InvokeLimiter


class TestBaseHoneypot:
    # noinspection PyAbstractClass
    def test_base_honeypot(self):
        with pytest.raises(
            TypeError, match="Can't instantiate abstract class BaseHoneypot"
        ):
            BaseHoneypot()


class TestHoneypotUtils:
    def test_allocate_port(self):
        port = allocate_port()
        assert isinstance(port, int)
        assert 1024 <= port <= 65535


class TestInvokeLimiter:
    def test_invoke_limit(self):
        limiter = InvokeLimiter(2, 1)
        for _ in range(2):
            assert limiter.can_invoke("v1")
        for _ in range(2):
            assert not limiter.can_invoke("v1")
        for _ in range(2):
            assert limiter.can_invoke("v2")
        sleep(2)
        for _ in range(2):
            assert limiter.can_invoke("v1")
