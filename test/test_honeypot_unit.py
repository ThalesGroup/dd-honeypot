from base_honeypot import BaseHoneypot
import pytest


def test_base_honeypot():
    with pytest.raises(
        TypeError,
        match="Can't instantiate abstract class BaseHoneypot",
    ):
        BaseHoneypot()
