import pytest

from honeypot_utils import init_env_from_file
from llm_utils import invoke_llm


@pytest.fixture(autouse=True, scope="module")
def set_aws_api_key():
    init_env_from_file()


@pytest.mark.parametrize(
    "model_id",
    [
        "anthropic.claude-instant-v1",
        "anthropic.claude-v2",
        "anthropic.claude-3-5-sonnet-20240620-v1:0",
    ],
)
def test_connect_to_bedrock(model_id: str):
    question = "What is the capital of Japan?"
    answer = invoke_llm(
        "you are a helpful assistant who answer questions", question, model_id=model_id
    )
    assert "Tokyo" in answer
