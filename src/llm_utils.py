import json
import logging
from typing import Optional, List

import boto3
from botocore.config import Config


def get_model_ids() -> List[str]:
    return [
        "anthropic.claude-instant-v1",
        "anthropic.claude-v2:1",
        "anthropic.claude-3-5-sonnet-20240620-v1:0",
    ]


def invoke_llm(system_prompt: Optional[str], user_prompt: str, model_id: str) -> str:
    logging.info(f"Going to invoke LLM. Model ID: {model_id}")
    prompt = _format_model_body(user_prompt, system_prompt, model_id)
    response_json = _invoke_bedrock_model(prompt, model_id)
    response_text = _get_response_content(response_json, model_id)
    logging.info(f"Got response from LLM. Response length: {len(response_text)}")
    return response_text


def _invoke_bedrock_model(prompt_body: dict, model_id: str) -> dict:
    bedrock_client = boto3.client(
        service_name="bedrock-runtime", config=Config(read_timeout=300)
    )
    response = bedrock_client.invoke_model(
        body=json.dumps(prompt_body),
        modelId=model_id,
    )
    return json.loads(response.get("body").read())


def _format_model_body(
    prompt: str, system_prompt: Optional[str], model_id: str
) -> dict:
    if system_prompt is None:
        system_prompt = "You are a SQL generator helper"
    if "claude" in model_id:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "system": system_prompt,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "max_tokens": 2000,
            "temperature": 0.0,
        }
    elif "jamba" in model_id:
        body = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "n": 1,
        }
    else:
        raise ValueError(f"Unknown model_id: {model_id}")
    return body


def _get_response_content(response_json: dict, model_id: str) -> str:
    if "claude" in model_id:
        return response_json["content"][0]["text"]
    elif "jamba" in model_id:
        return response_json["choices"][0]["message"]["content"]
    else:
        raise ValueError(f"Unknown model_id: {model_id}")

def is_bedrock_accessible() -> bool:
    try:
        client = boto3.client("bedrock-runtime", config=Config(read_timeout=5))
        # Try listing models or a simple describe call
        client.list_foundation_models()
        return True
    except Exception as e:
        logging.warning(f"Bedrock not accessible: {e}")
        return False

import os

RESPONSES_FILE = os.path.join(os.path.dirname(__file__), "responses.json")

def get_or_generate_response(query: str) -> str:
    # Load existing cache
    if os.path.exists(RESPONSES_FILE):
        with open(RESPONSES_FILE, "r") as f:
            cache = json.load(f)
    else:
        cache = {}

    if query in cache:
        logging.info(f"Cache hit for query: {query}")
        return cache[query]

    if not is_bedrock_accessible():
        logging.warning("Bedrock not accessible; returning dummy response")
        return "Simulated MySQL error or result (Bedrock unavailable)"

    try:
        response = invoke_llm(
            system_prompt="You are a MySQL server. Answer the query as if you are responding from a real MySQL database.",
            user_prompt=query,
            model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
        )
        cache[query] = response

        with open(RESPONSES_FILE, "w") as f:
            json.dump(cache, f, indent=2)

        return response
    except Exception as e:
        logging.error(f"LLM generation failed for query '{query}': {e}")
        return "LLM generation failed; simulated fallback"


