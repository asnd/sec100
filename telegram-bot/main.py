#!/usr/bin/env python3
"""
3GPP Telegram Bot - Main Entry Point

A Telegram bot for querying 3GPP public domain infrastructure.
Supports country search, MCC/MNC lookup, MSISDN parsing, and operator search.
"""

import asyncio
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes
)

from config import Config
from services.rate_limiter import RateLimiter
from services.database import Database
from utils.logger import setup_logger, get_logger
from handlers import help as help_handler
from handlers import country as country_handler
from handlers import mcc_mnc as mcc_mnc_handler
from handlers import msisdn as msisdn_handler
from handlers import operator as operator_handler

# Initialize logger
logger = setup_logger(level=Config.LOG_LEVEL, log_file=Config.LOG_FILE)
logger = get_logger("main")


# Global instances
rate_limiter = None
database = None


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle errors in the bot.

    Args:
        update: Telegram update
        context: Bot context with error information
    """
    logger.error(f"Update {update} caused error {context.error}", exc_info=context.error)

    # Try to inform user
    if update and update.effective_message:
        await update.effective_message.reply_text(
            "⚠️ An error occurred while processing your request. "
            "Please try again later or contact an administrator."
        )


async def rate_limit_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """
    Check rate limits before processing command.

    Args:
        update: Telegram update
        context: Bot context

    Returns:
        True if within limits, False otherwise (sends error message to user)
    """
    user_id = update.effective_user.id

    # Check rate limit
    allowed, message = rate_limiter.check_rate_limit(user_id)

    if not allowed:
        logger.warning(f"Rate limit exceeded for user {user_id}")
        await update.message.reply_text(message)
        return False

    # Record the query
    rate_limiter.record_query(user_id)
    return True


async def unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle unknown commands.

    Args:
        update: Telegram update
        context: Bot context
    """
    await update.message.reply_text(
        "❓ Unknown command. Use /help to see available commands."
    )


def main() -> None:
    """
    Main function to start the bot.
    """
    global rate_limiter, database

    # Validate configuration
    try:
        Config.validate()
        Config.print_config()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return

    # Initialize services
    logger.info("Initializing services...")

    rate_limiter = RateLimiter(
        max_per_minute=Config.MAX_QUERIES_PER_MINUTE,
        max_per_hour=Config.MAX_QUERIES_PER_HOUR,
        admin_user_ids=Config.ADMIN_USER_IDS
    )

    database = Database(Config.DB_PATH)

    # Create bot application
    logger.info("Creating bot application...")
    application = Application.builder().token(Config.TELEGRAM_BOT_TOKEN).build()

    # Register command handlers
    logger.info("Registering command handlers...")

    # Help commands
    application.add_handler(CommandHandler("start", help_handler.start_command))
    application.add_handler(CommandHandler("help", help_handler.help_command))

    # Query command handlers
    application.add_handler(CommandHandler("country", country_handler.country_command))
    application.add_handler(CommandHandler("mcc", mcc_mnc_handler.mcc_command))
    application.add_handler(CommandHandler("mnc", mcc_mnc_handler.mnc_command))
    application.add_handler(CommandHandler("phone", msisdn_handler.phone_command))
    application.add_handler(CommandHandler("operator", operator_handler.operator_command))

    # Unknown command handler (must be last)
    application.add_handler(MessageHandler(filters.COMMAND, unknown_command))

    # Error handler
    application.add_error_handler(error_handler)

    # Start the bot
    logger.info("Starting bot...")
    logger.info("Bot is now running. Press Ctrl+C to stop.")

    # Run the bot
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
