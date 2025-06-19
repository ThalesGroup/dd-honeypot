from typing import List

from infra.data_handler import DataHandler


class HTTPDataHandler(DataHandler):

    def __init__(self, data_file: str, system_prompt: str, model_id: str):
        super().__init__(
            data_file,
            "\n".join(system_prompt) + "\n".join(self.base_system_prompt()),
            model_id,
            {"path": "TEXT", "args": "TEXT", "body": "TEXT"},
        )

    @staticmethod
    def base_system_prompt() -> List[str]:
        return [
            "You should only respond with the content of the file requested, and nothing else",
            "Do not include any additional information or context",
            "If the file does not exist, return a 404 error message",
            "When you return an html include the most important parts actionable parts like forms, buttons, links, do not include images, javascript or other references",
            "The name, ids and titles MUST MATCH the original ones",
            "Login should always succeed",
        ]

    def request_user_prompt(self, req: dict) -> str:
        result = f"""Method: {req["method"]}
    path: {req["path"]}
    args: {req["args"]}
    resource_type: {req["resource_type"]}
    Headers: {req["headers"]}
    Body: {req["body"]}"""
        hint = self.user_prompt_hint(req)
        if hint:
            result += f"\nHere is AN IMPORTANT Hint regarding this request. You MUST follow it:\n{hint}"
        return result
