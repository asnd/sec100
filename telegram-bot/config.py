"""
Configuration management for 3GPP Telegram Bot.

Loads settings from environment variables with sensible defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Bot configuration loaded from environment variables."""

    # Telegram Bot
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    ADMIN_USER_IDS = [
        int(x.strip())
        for x in os.getenv("ADMIN_USER_IDS", "").split(",")
        if x.strip().isdigit()
    ]

    # Database
    DB_PATH = os.getenv(
        "DB_PATH",
        str(Path(__file__).parent.parent / "go-3gpp-scanner" / "bin" / "database.db")
    )

    # Rate Limiting (per user)
    MAX_QUERIES_PER_MINUTE = int(os.getenv("MAX_QUERIES_PER_MINUTE", "10"))
    MAX_QUERIES_PER_HOUR = int(os.getenv("MAX_QUERIES_PER_HOUR", "50"))

    # DNS Resolution
    DNS_RESOLUTION_TIMEOUT = int(os.getenv("DNS_RESOLUTION_TIMEOUT", "5"))
    DNS_CONCURRENT_WORKERS = int(os.getenv("DNS_CONCURRENT_WORKERS", "10"))

    # Pagination
    MAX_OPERATORS_PER_PAGE = int(os.getenv("MAX_OPERATORS_PER_PAGE", "5"))
    MAX_FQDNS_PER_OPERATOR = int(os.getenv("MAX_FQDNS_PER_OPERATOR", "10"))

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "bot.log")

    # Data Files
    MCC_MNC_JSON_PATH = os.getenv(
        "MCC_MNC_JSON_PATH",
        str(Path(__file__).parent.parent / "epdg" / "mcc-mnc-list.json")
    )

    @classmethod
    def validate(cls) -> None:
        """
        Validate configuration.

        Raises:
            ValueError: If required configuration is missing or invalid
        """
        if not cls.TELEGRAM_BOT_TOKEN:
            raise ValueError(
                "TELEGRAM_BOT_TOKEN is required. "
                "Set it in .env file or environment variable."
            )

        if not os.path.exists(cls.DB_PATH):
            raise ValueError(
                f"Database not found: {cls.DB_PATH}. "
                "Run migrations first or set correct DB_PATH."
            )

    @classmethod
    def print_config(cls) -> None:
        """Print current configuration (for debugging)."""
        print("="*60)
        print("3GPP Telegram Bot - Configuration")
        print("="*60)
        print(f"Bot Token: {'✓ Set' if cls.TELEGRAM_BOT_TOKEN else '✗ Not set'}")
        print(f"Admin Users: {len(cls.ADMIN_USER_IDS)}")
        print(f"Database: {cls.DB_PATH}")
        print(f"Rate Limits: {cls.MAX_QUERIES_PER_MINUTE}/min, {cls.MAX_QUERIES_PER_HOUR}/hour")
        print(f"DNS Workers: {cls.DNS_CONCURRENT_WORKERS} (timeout: {cls.DNS_RESOLUTION_TIMEOUT}s)")
        print(f"Pagination: {cls.MAX_OPERATORS_PER_PAGE} ops/page, {cls.MAX_FQDNS_PER_OPERATOR} FQDNs/op")
        print(f"Log Level: {cls.LOG_LEVEL}")
        print("="*60)
