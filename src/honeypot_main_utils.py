import asyncio
import logging
import os
import sys
from typing import List
from base_honeypot import BaseHoneypot
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


def start_dd_honeypot(folder: str):
    if not os.path.exists(folder):
        logging.error(f"Honeypot folder does not exist: {folder}")
        sys.exit(1)
    try:
        logging.info(f"Honeypots server started. Folder: {folder}")
        asyncio.run(_start_honeypots(folder))
    except Exception as e:
        logging.error(f"Error during honeypot startup: {e}")
    finally:
        logging.info("Honeypots server stopped")
