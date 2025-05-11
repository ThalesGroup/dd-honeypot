import logging
import os
import sys
from logging.config import fileConfig
from time import sleep


if __name__ == "__main__":
    fileConfig(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logging.conf"))
    from infra.honeypot_wrapper import create_honeypot_by_folder

    honeypot_folder = sys.argv[1] if len(sys.argv) > 1 else "/data/honeypot"
    logging.info(f"Honeypot main started. Folder: {honeypot_folder}")
    honeypot = create_honeypot_by_folder(honeypot_folder)
    try:
        honeypot.start()
        while honeypot.is_running():
            sleep(2)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")
    finally:
        logging.info("Stopping honeypot...")
        honeypot.stop()
