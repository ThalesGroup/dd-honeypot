import logging
import os
import sys
from logging.config import fileConfig

from honeypot_main_utils import start_dd_honeypot
from honeypot_utils import init_env_from_file

fileConfig(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logging.conf"))
logging.info("Configured logging")

if __name__ == "__main__":
    init_env_from_file()
    honeypot_folder = sys.argv[1] if len(sys.argv) > 1 else "/data/honeypot"
    start_dd_honeypot(honeypot_folder)
