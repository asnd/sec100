"""
Help and start command handlers.

Provides welcome message and command reference.
"""

from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from services.formatter import format_help_message, format_welcome_message
from utils.logger import get_logger

logger = get_logger("handlers.help")


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /start command.

    Shows welcome message to new users.
    """
    user = update.effective_user
    logger.info(f"Start command from user {user.id} (@{user.username})")

    message = format_welcome_message()

    await update.message.reply_text(
        message,
        parse_mode=ParseMode.HTML
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /help command.

    Shows command reference and usage examples.
    """
    user = update.effective_user
    logger.info(f"Help command from user {user.id} (@{user.username})")

    message = format_help_message()

    await update.message.reply_text(
        message,
        parse_mode=ParseMode.HTML
    )
