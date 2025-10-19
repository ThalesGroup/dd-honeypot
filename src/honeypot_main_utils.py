import asyncio
import json
import logging
import os
import sys
from typing import List, Tuple, Dict, Callable

from base_honeypot import BaseHoneypot
from honeypot_registry import get_honeypot_registry
from http_honeypot import HTTPHoneypot
from infra.data_handler import DataHandler
from infra.honeypot_wrapper import create_honeypot_by_folder


def _has_only_subdirectories(folder_path: str) -> bool:
    for sub_folder in os.listdir(folder_path):
        if not os.path.isdir(os.path.join(folder_path, sub_folder)):
            return False
    return True


# Check if a folder is a honeypot folder by looking for config.json
def _is_honeypot_folder(folder_path: str) -> bool:
    config_file = os.path.join(folder_path, "config.json")
    return os.path.isfile(config_file)


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


async def _start_components(root: str):
    folders = _scan_folders(root)
    has_dispatcher = any(cfg.get("is_dispatcher") for _, cfg in folders)
    logging.info(f"Dispatcher mode: {'ON' if has_dispatcher else 'OFF'}")

    if not has_dispatcher:
        # Legacy path unchanged
        honeypots: List[BaseHoneypot] = []
        for folder_path, _ in folders:
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

    # Dispatcher mode
    backend_handlers: Dict[str, Callable] = {}
    normal_honeypots: List[BaseHoneypot] = []
    dispatchers: List[BaseHoneypot] = []

    # Names of http backends referred by any dispatcher
    http_names_for_dispatchers = set()
    for _, cfg in folders:
        if cfg.get("is_dispatcher"):
            http_names_for_dispatchers.update(cfg.get("honeypots", []))

    # Instantiate all honeypots once
    created: Dict[str, BaseHoneypot] = {}
    for folder_path, cfg in folders:
        try:
            hp = create_honeypot_by_folder(folder_path)
            created[folder_path] = hp
        except Exception as ex:
            logging.error(f"Error creating honeypot from folder {folder_path}: {ex}")

    # Build backend registry and list of listeners to start
    for folder_path, cfg in folders:
        hp = created.get(folder_path)
        if not hp:
            continue
        if cfg.get("is_dispatcher"):
            dispatchers.append(hp)
            continue

        hp_type = cfg.get("type", "")
        name = cfg.get("name", "")

        if hp_type == "http" and name in http_names_for_dispatchers:
            # Do NOT start this listener; expose in-process handler for dispatcher
            try:
                if isinstance(hp, HTTPHoneypot):
                    handler = hp.as_backend_handler()
                    backend_handlers[name] = handler
                    logging.info(f"Registering in-process HTTP backend: {name}")
                else:
                    logging.warning(
                        f"Honeypot {name} is not an HTTPHoneypot; skipping backend handler registration."
                    )
            except Exception as ex:
                logging.error(f"Error building backend handler for {name}: {ex}")
            continue

        # All others start normally (tcp/mysql/ssh/http not behind dispatcher)
        normal_honeypots.append(hp)

    # Start normal listeners
    for h in normal_honeypots:
        try:
            if asyncio.iscoroutinefunction(h.start):
                await h.start()
            else:
                h.start()
        except Exception as ex:
            logging.error(f"Error starting honeypot {h}: {ex}")

    get_honeypot_registry().reset_honeypots()
    get_honeypot_registry().register_honeypots(normal_honeypots)

    # Start each dispatcher honeypot as an HTTP listener with wired backends
    for folder_path, cfg in folders:
        hp = created.get(folder_path)
        if not hp or not cfg.get("is_dispatcher"):
            continue

        names = cfg.get("honeypots", [])
        wired = {n: backend_handlers[n] for n in names if n in backend_handlers}

        # Create and start the dispatcher honeypot with routes and backends
        port = cfg.get("port")
        routes = _load_dispatcher_routes(folder_path)

        action = DataHandler(
            data_file=os.path.join(folder_path, "data.jsonl"),
            system_prompt=cfg.get("system_prompt", ""),
            model_id=cfg.get("model_id", ""),
            structure=None,
            routes=routes,
        )

        dispatcher_hp = HTTPHoneypot(
            port=port,
            action=action,
            config=cfg,
            inprocess_backends=wired,
        )
        dispatcher_hp.start()
        dispatchers.append(dispatcher_hp)

    # Run until STOP_HONEYPOT=true
    try:
        while os.getenv("STOP_HONEYPOT", "false") != "true":
            if not any(h.is_running() for h in normal_honeypots):
                await asyncio.sleep(0.5)
            await asyncio.sleep(1)
        logging.info("Stopping honeypot")
        for h in normal_honeypots + dispatchers:
            try:
                if h.is_running():
                    h.stop()
            except OSError:
                pass
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
