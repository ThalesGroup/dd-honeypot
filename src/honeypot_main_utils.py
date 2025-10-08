import asyncio
import json
import logging
import os
import sys
from typing import List, Tuple, Dict
from base_honeypot import BaseHoneypot
from infra.honeypot_wrapper import create_honeypot_by_folder
from http_dispatcher import start_dispatcher


def _has_only_subdirectories(folder_path: str) -> bool:
    for sub_folder in os.listdir(folder_path):
        if not os.path.isdir(os.path.join(folder_path, sub_folder)):
            return False
    return True


# Check if a folder is a honeypot folder by looking for config.json
def _is_honeypot_folder(folder_path: str) -> bool:
    config_file = os.path.join(folder_path, "config.json")
    return os.path.isfile(config_file)


# Collect and create honeypot instances from the given folder
def _collect_honeypots(folder) -> List[BaseHoneypot]:
    honeypots: List[BaseHoneypot] = []
    if _has_only_subdirectories(folder):
        logging.info(
            f"Found subdirectories in honeypot folder: {folder}. Adding honeypots"
        )
        for sub_folder in os.listdir(folder):
            folder_path = os.path.join(folder, sub_folder)
            if _is_honeypot_folder(folder_path):
                logging.info(f"Found honeypot folder: {folder_path}")
                try:
                    honeypots.append(create_honeypot_by_folder(folder_path))
                except Exception as ex:
                    logging.error(
                        f"Error creating honeypot from folder {folder_path}: {ex}"
                    )
    else:
        honeypots.append(create_honeypot_by_folder(folder))
    return honeypots


async def _start_honeypots(folder: str):
    honeypots = _collect_honeypots(folder)
    logging.info(f"Found {len(honeypots)} honeypots. Starting...")
    for h in honeypots:
        try:
            if asyncio.iscoroutinefunction(h.start):
                await h.start()
            else:
                h.start()
        except Exception as ex:
            logging.error(f"Error starting honeypot {h}: {ex}")
    try:
        while os.getenv("STOP_HONEYPOT", "false") != "true" and any(
            h.is_running() for h in honeypots
        ):
            await asyncio.sleep(2)
        logging.info("Stopping honeypot")
        for h in honeypots:
            if h.is_running():
                h.stop()
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")


def _load_dispatcher_routes(folder_path: str) -> List[dict]:
    # Look for dispatcher_data.jsonl or data.jsonl inside the dispatcher folder
    for name in ("dispatcher_data.jsonl", "data.jsonl"):
        p = os.path.join(folder_path, name)
        if os.path.exists(p):
            out = []
            with open(p, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    out.append(json.loads(line))
            return out
    return []


def _load_config(folder_path: str) -> dict:
    with open(os.path.join(folder_path, "config.json"), "r") as f:
        return json.load(f)


def _scan_folders(root: str) -> List[Tuple[str, dict]]:
    folders = []
    if _has_only_subdirectories(root):
        logging.info(
            f"Found subdirectories in honeypot folder: {root}. Adding honeypots"
        )
        for sub in os.listdir(root):
            p = os.path.join(root, sub)
            if _is_honeypot_folder(p):
                try:
                    cfg = _load_config(p)
                    folders.append((p, cfg))
                    logging.info(f"Found honeypot folder: {p}")
                except Exception as ex:
                    logging.error(f"Error reading config from {p}: {ex}")
    else:
        folders.append((root, _load_config(root)))
    return folders


def build_http_backend_handler(cfg: dict):
    """
    Return a callable(req_dict) -> (status, headers, body)
    Keep it small; generate HTML/JSON strings; do not bind a socket.
    Replace this stub with your real HTTP data handler factory if available.
    """
    name = cfg["name"]

    def handler(req):
        p = (req.get("path_only") or req.get("path") or "/").lower()
        if name == "php_my_admin":
            if "/phpmyadmin" in p:
                return 200, {"Content-Type": "text/html"}, "<html>phpMyAdmin</html>"
            return 200, {"Content-Type": "text/html"}, "<html>phpMyAdmin home</html>"
        if name == "boa_server_http":
            if "/login.htm" in p:
                return 200, {"Content-Type": "text/html"}, "<html>Boa login</html>"
            return 200, {"Content-Type": "text/html"}, "<html>Boa home</html>"
        return 200, {"Content-Type": "text/html"}, "<html>OK</html>"

    return handler


async def _start_components(root: str):
    folders = _scan_folders(root)
    has_dispatcher = any(cfg.get("is_dispatcher") for _, cfg in folders)
    logging.info(f"Dispatcher mode: {'ON' if has_dispatcher else 'OFF'}")

    if not has_dispatcher:
        # Legacy: start every honeypot as a real listener
        honeypots: List[BaseHoneypot] = []
        for folder_path, cfg in folders:
            try:
                hp = create_honeypot_by_folder(folder_path)
                honeypots.append(hp)
            except Exception as ex:
                logging.error(
                    f"Error creating honeypot from folder {folder_path}: {ex}"
                )

        logging.info(f"Found {len(honeypots)} honeypots. Starting...")
        for h in honeypots:
            try:
                if asyncio.iscoroutinefunction(h.start):
                    await h.start()
                else:
                    h.start()
            except Exception as ex:
                logging.error(f"Error starting honeypot {h}: {ex}")

        try:
            while os.getenv("STOP_HONEYPOT", "false") != "true" and any(
                h.is_running() for h in honeypots
            ):
                await asyncio.sleep(2)
            logging.info("Stopping honeypot")
            for h in honeypots:
                if h.is_running():
                    h.stop()
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt received")
        return

    # Dispatcher mode: register in-process HTTP backends listed by dispatcher(s),
    # start non-http (and http not listed) as normal listeners.
    backend_handlers: Dict[str, callable] = {}
    normal_honeypots: List[BaseHoneypot] = []

    # Gather all http names used by any dispatcher
    http_names_for_dispatchers = set()
    for _, cfg in folders:
        if cfg.get("is_dispatcher"):
            http_names_for_dispatchers.update(cfg.get("honeypots", []))

    for folder_path, cfg in folders:
        if cfg.get("is_dispatcher"):
            continue
        hp_type = cfg.get("type", "")
        name = cfg.get("name", "")
        if hp_type == "http" and name in http_names_for_dispatchers:
            backend_handlers[name] = build_http_backend_handler(cfg)
            logging.info(f"Registering in-process HTTP backend: {name}")
            continue
        try:
            hp = create_honeypot_by_folder(folder_path)
            normal_honeypots.append(hp)
        except Exception as ex:
            logging.error(f"Error creating honeypot from folder {folder_path}: {ex}")

    # Start non-dispatched listeners
    for h in normal_honeypots:
        try:
            if asyncio.iscoroutinefunction(h.start):
                await h.start()
            else:
                h.start()
        except Exception as ex:
            logging.error(f"Error starting honeypot {h}: {ex}")

    # Start each dispatcher as the only HTTP listener for those backends
    for folder_path, cfg in folders:
        if not cfg.get("is_dispatcher"):
            continue
        port = int(cfg.get("port") or 0)
        routes = _load_dispatcher_routes(folder_path)
        names = cfg.get("honeypots", [])
        backends = {n: backend_handlers[n] for n in names if n in backend_handlers}

        sys_prompt = cfg.get("system_prompt", [])
        for n in names:
            for fpath, bcfg in folders:
                if bcfg.get("name") == n and "description" in bcfg:
                    sys_prompt.append(f"[{n}] {bcfg['description']}")

        logging.info(
            f"Starting HTTP dispatcher on port {port} for {list(backends)} with {len(routes)} routes"
        )
        start_dispatcher(
            port=port,
            routes=routes,
            backends=backends,
            model_id=cfg.get("model_id"),
            system_prompt=sys_prompt,
        )

    try:
        while os.getenv("STOP_HONEYPOT", "false") != "true":
            if not any(h.is_running() for h in normal_honeypots):
                await asyncio.sleep(0.5)
            await asyncio.sleep(1)
        logging.info("Stopping honeypot")
        for h in normal_honeypots:
            if h.is_running():
                h.stop()
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")


def start_dd_honeypot(folder: str):
    if not os.path.exists(folder):
        logging.error(f"Honeypot folder does not exist: {folder}")
        sys.exit(1)
    try:
        logging.info(f"Honeypots server started. Folder: {folder}")
        asyncio.run(_start_components(folder))
    except Exception as e:
        logging.error(f"Error during honeypot startup: {e}")
    finally:
        logging.info("Honeypots server stopped")
