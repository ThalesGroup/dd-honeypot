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


# SSH Dispatch


@pytest.fixture
def ssh_dispatcher():
    """Mock dispatcher for SSH protocol routing"""

    class MockSSHDispatcher:
        def __init__(self):
            # SSH routing: commands to backend services
            self.routes = {
                "ls": "mysql_ssh",
                "mysql -u root -p": "mysql_ssh",  # initial
                "SELECT 1": "mysql",  # After protocol switch
                "exit": "mysql_ssh",  # Switch back
            }
            self.backends = {"mysql_ssh", "mysql"}

        def get_handler_by_name(self, name):
            return {"name": name} if name in self.backends else None

        def classify(self, command, session=None):
            if session and "mode" in session:
                current_mode = session["mode"]
                # Switching back to SSH from MySQL
                if current_mode == "mysql" and command == "exit":
                    session["mode"] = "mysql_ssh"
                    session["backend_name"] = "mysql_ssh"
                    return "mysql_ssh"
                # Handle commands while in mysql mode (protocol switched)
                elif current_mode == "mysql":
                    session["backend_name"] = "mysql"
                    return "mysql"
            # Initial SSH routing
            if command in self.routes:
                backend = self.routes[command]
                if session is not None:
                    if command == "mysql -u root -p":
                        session["mode"] = "mysql"
                        session["backend_name"] = "mysql"
                    else:
                        session["mode"] = "mysql_ssh"
                        session["backend_name"] = "mysql_ssh"
                return backend
            else:
                # Unknown command, stay in current backend
                if session is not None:
                    return session.get("backend_name", "mysql_ssh")
                return "mysql_ssh"

    return MockSSHDispatcher()


@pytest.fixture
def ssh_client(ssh_dispatcher, session_store):
    """Mock SSH client for testing"""

    class FakeSSHClient:
        def __init__(self):
            self.last_session_id = 0

        def send_command(self, command, session_id=None):
            # Create or get session
            if session_id is None:
                self.last_session_id += 1
                session_id = f"ssh_{self.last_session_id}"

            session = session_store.setdefault(session_id, {"mode": "mysql_ssh"})

            # Route command
            backend_name = ssh_dispatcher.classify(command, session)

            # Mock response
            class SSHResponse:
                def __init__(self, backend, session_id):
                    self.backend_name = session.get("backend_name", backend)
                    self.session_id = session_id
                    self.mode = session.get("mode", "mysql_ssh")

            return SSHResponse(backend_name, session_id)

    return FakeSSHClient()


# SSH Test Cases
def test_ssh_dispatcher_initial_commands(ssh_client, ssh_dispatcher, session_store):
    """Test basic SSH commands route to mysql_ssh backend"""
    resp = ssh_client.send_command("ls")
    assert resp.backend_name == "mysql_ssh"
    assert resp.mode == "mysql_ssh"

    handler = ssh_dispatcher.get_handler_by_name("mysql_ssh")
    assert handler is not None
    assert handler["name"] == "mysql_ssh"


def test_ssh_to_mysql_protocol_switch(ssh_client, ssh_dispatcher, session_store):
    """Test SSH to MySQL protocol switching"""
    # Start with SSH command
    resp1 = ssh_client.send_command("ls")
    session_id = resp1.session_id
    assert resp1.backend_name == "mysql_ssh"
    assert resp1.mode == "mysql_ssh"

    # Switch to MySQL
    resp2 = ssh_client.send_command("mysql -u root -p", session_id)
    # Here the backend switches IMMEDIATELY to "mysql"
    assert resp2.backend_name == "mysql"
    assert resp2.mode == "mysql"  # Mode also changes

    # Now in MySQL mode - SQL commands
    resp3 = ssh_client.send_command("SELECT 1", session_id)
    assert resp3.backend_name == "mysql"  # Now routed to MySQL backend
    assert resp3.mode == "mysql"


def test_mysql_to_ssh_protocol_switch_back(ssh_client, ssh_dispatcher, session_store):
    """Test MySQL back to SSH protocol switching"""
    # Start in MySQL mode (simulate previous switch)
    session_id = "test_mysql_session"
    session_store[session_id] = {"mode": "mysql", "backend_name": "mysql"}

    # Exit MySQL - should switch back to SSH
    resp = ssh_client.send_command("exit", session_id)
    assert resp.backend_name == "mysql_ssh"
    assert resp.mode == "mysql_ssh"

    # Verify we're back in SSH mode
    resp2 = ssh_client.send_command("ls", session_id)
    assert resp2.backend_name == "mysql_ssh"
    assert resp2.mode == "mysql_ssh"


def test_ssh_session_consistency(ssh_client, ssh_dispatcher, session_store):
    """Test session state persists across commands"""
    resp1 = ssh_client.send_command("ls")
    session_id = resp1.session_id

    # Multiple commands in same session should maintain state
    resp2 = ssh_client.send_command("ls", session_id)
    resp3 = ssh_client.send_command("ls", session_id)

    assert resp1.session_id == resp2.session_id == resp3.session_id
    assert resp1.mode == resp2.mode == resp3.mode == "mysql_ssh"


def test_unknown_ssh_command_routing(ssh_client, ssh_dispatcher, session_store):
    """Test unknown commands stay in current backend"""
    resp1 = ssh_client.send_command("unknown_command")
    assert resp1.backend_name == "mysql_ssh"  # Should default to SSH backend

    # Unknown command in established session should maintain current backend
    session_id = resp1.session_id
    resp2 = ssh_client.send_command("another_unknown_cmd", session_id)
    assert resp2.backend_name == "mysql_ssh"
    assert resp2.session_id == session_id
