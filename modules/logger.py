# =============================================================
# modules/logger.py
# Logging and Alert System
# =============================================================
# Provides two log destinations:
#   1. A rotating file log   → logs/<date>_alerts.log
#   2. Coloured terminal output for real-time alerts
#
# All log messages include a timestamp, severity level, and a
# human-readable description.
# =============================================================

import os
import logging
from datetime import datetime

from colorama import Fore, Style

from modules.utils import timestamp


# ------------------------------------------------------------------
# Module-level logger setup
# ------------------------------------------------------------------

# Directory where log files are stored
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")

# Make sure the logs directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Generate a log filename based on today's date
_log_filename = datetime.now().strftime("%Y-%m-%d") + "_alerts.log"
_log_filepath = os.path.join(LOG_DIR, _log_filename)

# Create a dedicated logger (avoid polluting the root logger)
logger = logging.getLogger("PacketSnifferARP")
logger.setLevel(logging.DEBUG)

# File handler — writes DEBUG and above to the daily log file
_file_handler = logging.FileHandler(_log_filepath, encoding="utf-8")
_file_handler.setLevel(logging.DEBUG)
_file_fmt = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_file_handler.setFormatter(_file_fmt)
logger.addHandler(_file_handler)


# ------------------------------------------------------------------
# Public Logging Functions
# ------------------------------------------------------------------

def log_info(message):
    """
    Log an informational message to the file and print it in
    green to the terminal.

    Args:
        message (str): The message to log.
    """
    logger.info(message)
    print(f"{Fore.GREEN}[INFO]  {timestamp()} | {message}{Style.RESET_ALL}")


def log_warning(message):
    """
    Log a warning message (potential issue) to the file and print
    it in yellow to the terminal.

    Args:
        message (str): The message to log.
    """
    logger.warning(message)
    print(f"{Fore.YELLOW}[WARN]  {timestamp()} | {message}{Style.RESET_ALL}")


def log_alert(message):
    """
    Log a critical security alert to the file and print it in
    bright red to the terminal.  Used for ARP spoofing detections.

    Args:
        message (str): The alert message.
    """
    logger.critical(message)
    print(
        f"{Fore.RED}{Style.BRIGHT}"
        f"[ALERT] {timestamp()} | !! {message}"
        f"{Style.RESET_ALL}"
    )


def log_error(message):
    """
    Log an error message to the file and print it in red.

    Args:
        message (str): The error description.
    """
    logger.error(message)
    print(f"{Fore.RED}[ERROR] {timestamp()} | {message}{Style.RESET_ALL}")


def log_debug(message):
    """
    Log a debug-level message to the file only (not printed to
    the terminal unless verbose mode is on).

    Args:
        message (str): The debug message.
    """
    logger.debug(message)


def log_packet_summary(summary, verbose=False):
    """
    Log a packet summary line.  Always written to the log file;
    printed to the terminal only in verbose mode.

    Args:
        summary (str): Formatted packet summary string.
        verbose (bool): If True, also print to the terminal.
    """
    logger.info(summary)
    if verbose:
        print(f"{Fore.WHITE}{summary}{Style.RESET_ALL}")


def get_log_filepath():
    """Return the absolute path of today's log file."""
    return _log_filepath
# Windows cp1252 output encoding fallback
