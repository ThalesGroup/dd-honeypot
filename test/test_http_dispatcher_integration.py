import pytest
import requests

from conftest import get_honeypot_main


@pytest.mark.skip("Enable when HTTP dispatcher is implemented")
def test_http_dispatcher_routing(monkeypatch):
    """
    End-to-end dispatcher integration using get_honeypot_main:
    - Starts two backend HTTP honeypots plus one dispatcher
    - Feeds the dispatcher's data.jsonl with the TL routing rules
    - Verifies routing by issuing real HTTP requests
    - Tests session persistence across multiple requests
    """

    honeypot_configs = [
        {"type": "http", "name": "php_my_admin", "port": 0},
        {"type": "http", "name": "boa_server_http", "port": 0},
        {
            "type": "http",
            "name": "http dispatcher",
            "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "system_prompt": [
                "You are an http dispatcher. You have to decide the right application target according to the given payload",
                "If there is no way to understand which application is the right target return UNKNOWN and choose one of the application",
            ],
            "honeypots": ["php_my_admin", "boa_server_http"],
            "port": 0,
        },
    ]

    dispatcher_data = [
        {"path": "/", "name": "UNKNOWN"},
        {"path": "/phpmyadmin", "name": "php_my_admin"},
        {"path": "/dbadmin", "name": "php_my_admin"},
        {"path": "/login.htm", "name": "boa_server_http"},
    ]

    with get_honeypot_main(
        monkeypatch,
        honeypot_configs=honeypot_configs,
        data_jsonl=dispatcher_data,
        fake_fs_jsonl=None,
    ) as dispatcher_port:
        base_url = f"http://127.0.0.1:{dispatcher_port}"

        session1 = requests.Session()

        resp1a = session1.get(f"{base_url}/phpmyadmin", timeout=5)
        assert resp1a.status_code == 200
        assert "phpmyadmin" in resp1a.text.lower()

        # Follow-up request in same session should go to same backend
        resp1b = session1.get(f"{base_url}/phpmyadmin?cmd=version", timeout=5)
        assert resp1b.status_code == 200
        assert "phpmyadmin" in resp1b.text.lower()

        session2 = requests.Session()

        resp2a = session2.get(f"{base_url}/login.htm", timeout=5)
        assert resp2a.status_code == 200
        assert "boa" in resp2a.text.lower() or "login" in resp2a.text.lower()

        # Follow-up request in same session should go to same backend
        resp2b = session2.get(f"{base_url}/login.htm?action=auth", timeout=5)
        assert resp2b.status_code == 200
        assert "boa" in resp2b.text.lower() or "login" in resp2b.text.lower()

        # UNKNOWN (session consistency)
        session3 = requests.Session()

        resp3a = session3.get(f"{base_url}/", timeout=5)
        assert resp3a.status_code == 200

        # Second call should go to SAME backend (session persistence)
        resp3b = session3.get(f"{base_url}/", timeout=5)
        assert resp3b.status_code == 200
        # Should be consistent with first response
        assert resp3a.text == resp3b.text or "consistent" in resp3b.text.lower()
