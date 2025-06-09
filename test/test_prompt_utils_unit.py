from infra.prompt_utils import render_prompt


def test_render_prompt_basic():
    session = {"username": "root", "cwd": "/"}
    tpl = "{{username}}@alpine:{{cwd}}$ "
    result = render_prompt(tpl, session)
    assert result == "root@alpine:/$ "


def test_render_prompt_missing_fields():
    session = {}
    tpl = "{{username}}@host:{{cwd}}$ "
    result = render_prompt(tpl, session)
    assert result == "user@host:/$ "
