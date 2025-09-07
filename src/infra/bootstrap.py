import json
from pathlib import Path

from http_data_handlers import HTTPDataHandler
from infra.interfaces import HoneypotAction
from infra.protocol_dispatcher import ProtocolDispatcher
from ssh_honeypot import SSHHoneypot

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

backend_map_http = {
    "php_my_admin": HTTPDataHandler("dummy.jsonl", "system_prompt", "model_id"),
    "boa_server_http": HTTPDataHandler("dummy.jsonl", "system_prompt", "model_id"),
}

backend_map_ssh = {
    "mysql_ssh": SSHHoneypot(),
}

disp_config_path = CONFIG_DIR / "http_dispatcher/config.json"

with open(disp_config_path) as f:
    http_config = json.load(f)
http_dispatcher = ProtocolDispatcher(http_config, backend_map_http)

with open(ssh_config_path) as f:
    ssh_config = json.load(f)
ssh_dispatcher = ProtocolDispatcher(ssh_config, backend_map_ssh)


__all__ = ["http_dispatcher", "ssh_dispatcher"]
