def render_prompt(template: str, session: dict) -> str:
    cwd = session.get("cwd", "/")
    username = session.get("username", "user")
    return template.replace("{{cwd}}", cwd).replace("{{username}}", username)
