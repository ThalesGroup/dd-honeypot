import inspect
import logging
import os
import sys
from logging.config import fileConfig
from time import sleep
from typing import List
import asyncio


# Load logging configuration from logging.conf
fileConfig(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logging.conf"))

from base_honeypot import BaseHoneypot
from honeypot_utils import init_env_from_file
from infra.honeypot_wrapper import create_honeypot_by_folder

# Check if the folder contains only subdirectories (no files)
def _has_only_subdirectories(folder_path: str) -> bool:
    for sub_folder in os.listdir(folder_path):
        if not os.path.isdir(os.path.join(folder_path, sub_folder)):
            return False
    return True

# Check if a folder is a honeypot folder by looking for config.json
def _is_honeypot_folder(folder_path: str) -> bool:
    config_file = os.path.join(folder_path, "config.json")
    return os.path.isfile(config_file)

# Start all honeypots in the given folder (sync or async)
def start(folder: str):
    honeypots = _collect_honeypots(folder)
    logging.info(f"Found {len(honeypots)} honeypots. Starting...")

    any_async = any(inspect.iscoroutinefunction(h.start) for h in honeypots)
    if any_async:
        asyncio.run(_start_async(honeypots))
    else:
        _start_sync(honeypots)

# Start all honeypots asynchronously and keep them running
async def _start_async(honeypots: List[BaseHoneypot]):
    try:
        for h in honeypots:
            start_fn = h.start
            if inspect.iscoroutinefunction(start_fn):
                await start_fn()
            else:
                start_fn()

        while any(h.is_running() for h in honeypots):
            await asyncio.sleep(2)

    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")
    finally:
        logging.info("Stopping honeypots...")
        for h in honeypots:
            stop_fn = h.stop
            if inspect.iscoroutinefunction(stop_fn):
                await stop_fn()
            else:
                stop_fn()

# Start all honeypots synchronously and keep them running
def _start_sync(honeypots: List[BaseHoneypot]):
    try:
        for h in honeypots:
            h.start()
        while any(h.is_running() for h in honeypots):
            sleep(2)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")
    finally:
        logging.info("Stopping honeypots...")
        for h in honeypots:
            if h.is_running():
                h.stop()

# Collect and create honeypot instances from the given folder(s)
def _collect_honeypots(folder) -> List[BaseHoneypot]:
    honeypots: List[BaseHoneypot] = []
    if _has_only_subdirectories(folder):
        logging.info(
            f"Found subdirectories in honeypot folder: {folder}. Adding honeypots"
        )
        for sub_folder in os.listdir(folder):
            folder_path = os.path.join(folder, sub_folder)
            if _is_honeypot_folder(folder_path):
                honeypots.append(create_honeypot_by_folder(folder_path))
    else:
        honeypots.append(create_honeypot_by_folder(folder))
    return honeypots

# Entry point: initialize environment, validate folder, and start honeypots
if __name__ == "__main__":
    init_env_from_file()
    honeypot_folder = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(os.path.dirname(__file__), "../test/honeypots")
    )

    if not os.path.exists(honeypot_folder):
        logging.error(f"Honeypot folder does not exist: {honeypot_folder}")
        sys.exit(1)

    try:
        logging.info(f"Honeypots server started. Folder: {honeypot_folder}")
        start(honeypot_folder)
    finally:
        logging.info("Honeypots server stopped")
        sys.exit(0)
