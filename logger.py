"""
logger.py - Logging utility for CamRadar.

Provides a centralized logging system that writes to both
the console and a log file at logs/camradar.log.
"""

import logging
import os


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "camradar.log")


def get_logger(name: str = "camradar") -> logging.Logger:
    """
    Return a configured logger instance.

    The logger outputs INFO-level messages to the console and writes
    DEBUG-level (and above) messages to *logs/camradar.log*.

    Args:
        name: Name for the logger (default ``"camradar"``).

    Returns:
        A :class:`logging.Logger` ready for use.
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers when get_logger is called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ---- File handler ----
    os.makedirs(LOG_DIR, exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)

    # ---- Console handler ----
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
