"""
MCC/MNC query handlers for /mcc and /mnc commands.

Allows users to query operators by Mobile Country Code and Mobile Network Code.
"""

from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from services.database import Database
from services.ip_resolver import get_operator_infrastructure
from services.formatter import format_mcc_response, format_error_message
from config import Config
from utils.logger import get_logger

logger = get_logger("handlers.mcc_mnc")


async def mcc_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /mcc command.

    Usage: /mcc <code>
    Example: /mcc 232

    Args:
        update: Telegram update
        context: Bot context
    """
    user = update.effective_user
    logger.info(f"MCC command from user {user.id} (@{user.username})")

    # Parse command arguments
    if not context.args:
        await update.message.reply_text(
            format_error_message(
                "invalid_input",
                "Please provide an MCC code.\nExample: /mcc 232"
            ),
            parse_mode=ParseMode.HTML
        )
        return

    try:
        mcc = int(context.args[0])
    except ValueError:
        await update.message.reply_text(
            format_error_message(
                "invalid_input",
                "MCC must be a number.\nExample: /mcc 232"
            ),
            parse_mode=ParseMode.HTML
        )
        return

    logger.info(f"Searching for MCC: {mcc}")

    # Validate MCC range
    if not (0 <= mcc <= 999):
        await update.message.reply_text(
            format_error_message(
                "invalid_input",
                "MCC must be between 0 and 999."
            ),
            parse_mode=ParseMode.HTML
        )
        return

    # Send "typing" action
    await update.message.chat.send_action("typing")

    try:
        # Initialize database
        db = Database(Config.DB_PATH)

        # Get operators for this MCC
        operators_data = await db.get_operators_by_mcc(mcc)

        if not operators_data:
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No operators found for MCC {mcc}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Send loading message
        loading_msg = await update.message.reply_text(
            f"⏳ Found {len(operators_data)} operator(s). Resolving IPs...",
            parse_mode=ParseMode.HTML
        )

        # Group operators and get infrastructure
        operators_dict = {}
        for op_data in operators_data:
            op_name = op_data["operator"]
            if op_name not in operators_dict:
                operators_dict[op_name] = []
            operators_dict[op_name].append((op_data["mnc"], op_data["mcc"]))

        # Resolve infrastructure
        operator_results = []
        for op_name, mnc_mcc_pairs in operators_dict.items():
            fqdns = await db.get_fqdns_by_operator(op_name)
            if fqdns:
                infrastructure = get_operator_infrastructure(
                    operator_name=op_name,
                    fqdns=fqdns,
                    mnc_mcc_pairs=mnc_mcc_pairs,
                    max_workers=Config.DNS_CONCURRENT_WORKERS,
                    timeout=Config.DNS_RESOLUTION_TIMEOUT
                )
                operator_results.append(infrastructure)

        # Delete loading message
        await loading_msg.delete()

        if not operator_results:
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No active infrastructure found for MCC {mcc}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Format and send response
        response = format_mcc_response(
            mcc=mcc,
            operators=operator_results,
            page=1,
            total_pages=1,
            max_operators_per_page=Config.MAX_OPERATORS_PER_PAGE,
            max_fqdns_per_operator=Config.MAX_FQDNS_PER_OPERATOR
        )

        await update.message.reply_text(
            response,
            parse_mode=ParseMode.HTML
        )

        # Log query
        await db.log_query(
            telegram_user_id=user.id,
            query_type="mcc",
            query_value=str(mcc),
            result_count=len(operator_results)
        )

    except Exception as e:
        logger.error(f"Error in MCC command: {e}", exc_info=True)
        await update.message.reply_text(
            format_error_message("db_error"),
            parse_mode=ParseMode.HTML
        )


async def mnc_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /mnc command.

    Usage: /mnc <mnc> <mcc>
    Example: /mnc 1 232

    Args:
        update: Telegram update
        context: Bot context
    """
    user = update.effective_user
    logger.info(f"MNC command from user {user.id} (@{user.username})")

    # Parse command arguments
    if len(context.args) < 2:
        await update.message.reply_text(
            format_error_message(
                "invalid_input",
                "Please provide both MNC and MCC.\nExample: /mnc 1 232"
            ),
            parse_mode=ParseMode.HTML
        )
        return

    try:
        mnc = int(context.args[0])
        mcc = int(context.args[1])
    except ValueError:
        await update.message.reply_text(
            format_error_message(
                "invalid_input",
                "MNC and MCC must be numbers.\nExample: /mnc 1 232"
            ),
            parse_mode=ParseMode.HTML
        )
        return

    logger.info(f"Searching for MNC: {mnc}, MCC: {mcc}")

    # Validate ranges
    if not (0 <= mnc <= 999):
        await update.message.reply_text(
            format_error_message("invalid_input", "MNC must be between 0 and 999."),
            parse_mode=ParseMode.HTML
        )
        return

    if not (0 <= mcc <= 999):
        await update.message.reply_text(
            format_error_message("invalid_input", "MCC must be between 0 and 999."),
            parse_mode=ParseMode.HTML
        )
        return

    # Send "typing" action
    await update.message.chat.send_action("typing")

    try:
        # Initialize database
        db = Database(Config.DB_PATH)

        # Get operators for this MNC-MCC pair
        operators_data = await db.get_operators_by_mnc_mcc(mnc, mcc)

        if not operators_data:
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No operators found for MNC {mnc}, MCC {mcc}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Send loading message
        loading_msg = await update.message.reply_text(
            f"⏳ Found {len(operators_data)} operator(s). Resolving IPs...",
            parse_mode=ParseMode.HTML
        )

        # Get infrastructure
        operator_results = []
        for op_data in operators_data:
            op_name = op_data["operator"]
            fqdns = await db.get_fqdns_by_operator(op_name)

            if fqdns:
                mnc_mcc_pairs = await db.get_mnc_mcc_pairs_by_operator(op_name)
                infrastructure = get_operator_infrastructure(
                    operator_name=op_name,
                    fqdns=fqdns,
                    mnc_mcc_pairs=mnc_mcc_pairs,
                    max_workers=Config.DNS_CONCURRENT_WORKERS,
                    timeout=Config.DNS_RESOLUTION_TIMEOUT
                )
                operator_results.append(infrastructure)

        # Delete loading message
        await loading_msg.delete()

        if not operator_results:
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No active infrastructure found for MNC {mnc}, MCC {mcc}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Format and send response
        response = format_mcc_response(
            mcc=mcc,
            operators=operator_results,
            page=1,
            total_pages=1,
            max_operators_per_page=Config.MAX_OPERATORS_PER_PAGE,
            max_fqdns_per_operator=Config.MAX_FQDNS_PER_OPERATOR
        )

        await update.message.reply_text(
            response,
            parse_mode=ParseMode.HTML
        )

        # Log query
        await db.log_query(
            telegram_user_id=user.id,
            query_type="mnc",
            query_value=f"{mnc}-{mcc}",
            result_count=len(operator_results)
        )

    except Exception as e:
        logger.error(f"Error in MNC command: {e}", exc_info=True)
        await update.message.reply_text(
            format_error_message("db_error"),
            parse_mode=ParseMode.HTML
        )
