from infra.protocol_dispatcher import ProtocolDispatcher
import json
from infra.interfaces import HoneypotAction

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
CONFIG_DIR = PROJECT_ROOT / "test/honeypots"

http_config_path = CONFIG_DIR / "php_my_admin/config.json"
ssh_config_path = CONFIG_DIR / "alpine/config.json"


def create_http_honeypot():
    from http_honeypot import (
        HTTPHoneypot,
    )

    with open(http_config_path) as f:
        http_config = json.load(f)
    http_action = HoneypotAction()
    return HTTPHoneypot(
        port=http_config["port"], action=http_action, config=http_config
    )


def create_ssh_honeypot():
    from ssh_honeypot import SSHHoneypot

    with open(ssh_config_path) as f:
        ssh_config = json.load(f)
    ssh_action = HoneypotAction()
    return SSHHoneypot(port=ssh_config["port"], action=ssh_action, config=ssh_config)


http_hp = create_http_honeypot()
ssh_hp = create_ssh_honeypot()

http_dispatcher = ProtocolDispatcher({"main": http_hp})
ssh_dispatcher = ProtocolDispatcher({"main": ssh_hp})

__all__ = ["http_dispatcher", "ssh_dispatcher"]
