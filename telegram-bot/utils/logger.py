"""
Logging setup for 3GPP Telegram Bot.

Provides structured logging with file and console output.
"""

import logging
import sys
from pathlib import Path


def setup_logger(
    name: str = "telegram_bot",
    level: str = "INFO",
    log_file: str = "bot.log"
) -> logging.Logger:
    """
    Setup and configure logger.

    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file

    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    logger.handlers.clear()

    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    simple_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )

    # Console handler (simple format)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)

    # File handler (detailed format)
    try:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Failed to create file handler: {e}")

    return logger


# Create default logger instance
default_logger = setup_logger()


def get_logger(name: str = None) -> logging.Logger:
    """
    Get logger instance.

    Args:
        name: Logger name (uses default if None)

    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f"telegram_bot.{name}")
    return default_logger
