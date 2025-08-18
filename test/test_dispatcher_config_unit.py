import pytest


@pytest.fixture
def dispatcher():
    # Replace with your dispatcher initialization or a mock
    class MockDispatcher:
        def __init__(self):
            # Mapping of path to honeypot
            self.routes = {
                "/phpmyadmin": "php_my_admin",
                "/dbadmin": "php_my_admin",
                "/login.htm": "boa_server_http",
                "/": "UNKNOWN",  # Will choose randomly in this case
            }
            self.honeypots = {"php_my_admin", "boa_server_http"}

        def get_handler_by_name(self, name):
            # Return a mock handler object if exists
            return {"name": name} if name in self.honeypots else None

        def classify(self, path, session=None):
            name = self.routes.get(path)
            if name == "UNKNOWN":
                import random

                chosen = random.choice(list(self.honeypots))
                if session is not None:
                    session["honeypot_name"] = chosen
                return chosen
            elif name is not None:
                if session is not None:
                    session["honeypot_name"] = name
                return name
            else:
                # No match: persist session routing
                if session is not None:
                    return session.get("honeypot_name")
                return None

    return MockDispatcher()


@pytest.fixture
def session_store():
    # Session tracker: maps session IDs to session dicts
    return {}


@pytest.fixture
def client(dispatcher, session_store):
    # Fake client that always passes cookies/session
    class FakeHttpClient:
        def __init__(self):
            self.sessions = {}
            self.last_session_id = 0

        def get(self, url, cookies=None):
            # Parse path from URL
            path = "/" + url.split("/", 3)[-1].split("?", 1)[0]
            # Use cookie as session id, or create new
            if cookies is not None and "session_id" in cookies:
                sid = cookies["session_id"]
                session = session_store.setdefault(sid, {})
            else:
                # New session
                self.last_session_id += 1
                sid = str(self.last_session_id)
                session = session_store.setdefault(sid, {})
            # Simulate dispatcher classification
            honeypot_name = dispatcher.classify(path, session)

            # Response object mock
            class Response:
                meta = {"honeypot_name": session["honeypot_name"]}
                cookies = {"session_id": sid}

            return Response()

    return FakeHttpClient()


def test_dispatcher_routes_to_phpmyadmin(client, dispatcher, session_store):
    resp1 = client.get("http://localhost:80/phpmyadmin")
    assert resp1.meta["honeypot_name"] == "php_my_admin"

    # Continue session with cookies:
    resp2 = client.get(
        "http://localhost:80/phpmyadmin/dashboard", cookies=resp1.cookies
    )
    assert resp2.meta["honeypot_name"] == "php_my_admin"

    handler = dispatcher.get_handler_by_name("php_my_admin")
    assert handler is not None
    assert handler["name"] == "php_my_admin"


def test_dispatcher_routes_to_boa_server(client, dispatcher, session_store):
    resp1 = client.get("http://localhost:80/login.htm")
    assert resp1.meta["honeypot_name"] == "boa_server_http"

    resp2 = client.get(
        "http://localhost:80/login.htm?user=attacker", cookies=resp1.cookies
    )
    assert resp2.meta["honeypot_name"] == "boa_server_http"

    handler = dispatcher.get_handler_by_name("boa_server_http")
    assert handler is not None
    assert handler["name"] == "boa_server_http"


def test_dispatcher_random_selection_and_consistency(client, dispatcher, session_store):
    resp1 = client.get("http://localhost:80/")
    assert resp1.meta["honeypot_name"] in {"php_my_admin", "boa_server_http"}

    chosen = resp1.meta["honeypot_name"]
    # Session consistency: subsequent requests use same honeypot
    resp2 = client.get("http://localhost:80/somepage", cookies=resp1.cookies)
    assert resp2.meta["honeypot_name"] == chosen

    session_id = resp1.cookies["session_id"]
    session = session_store[session_id]
    assert session["honeypot_name"] == chosen
