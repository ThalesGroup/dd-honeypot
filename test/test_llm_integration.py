import pytest

from honeypot_utils import init_env_from_file
from llm_utils import invoke_llm


@pytest.fixture(autouse=True, scope="module")
def set_evn():
    init_env_from_file()
    yield


def test_llm_invoke():
    result = invoke_llm(
        system_prompt=None,
        user_prompt="What is the capital of India?",
        model_id="anthropic.claude-instant-v1",
    )
    assert "New Delhi" in result
