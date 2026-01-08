"""
Operator query handler for /operator command.

Allows users to search for operators by name with fuzzy matching.
"""

from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from services.database import Database
from services.ip_resolver import get_operator_infrastructure
from services.formatter import format_operator_response, format_error_message
from config import Config
from utils.logger import get_logger

logger = get_logger("handlers.operator")


async def operator_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /operator command.

    Usage: /operator <name>
    Example: /operator Vodafone

    Args:
        update: Telegram update
        context: Bot context
    """
    user = update.effective_user
    logger.info(f"Operator command from user {user.id} (@{user.username})")

    # Parse command arguments
    if not context.args:
        await update.message.reply_text(
            format_error_message(
                "invalid_input",
                "Please provide an operator name.\nExample: /operator Vodafone"
            ),
            parse_mode=ParseMode.HTML
        )
        return

    operator_name = " ".join(context.args)
    logger.info(f"Searching for operator: {operator_name}")

    # Send "typing" action
    await update.message.chat.send_action("typing")

    try:
        # Initialize database
        db = Database(Config.DB_PATH)

        # Try exact match first
        operators_data = await db.get_operators_by_name(operator_name, exact=True)

        # If no exact match, try fuzzy match
        if not operators_data:
            operators_data = await db.get_operators_by_name(operator_name, exact=False)

            if not operators_data:
                await update.message.reply_text(
                    format_error_message(
                        "no_results",
                        f"No operator found matching: {operator_name}\n\n"
                        f"Try using different keywords or check spelling."
                    ),
                    parse_mode=ParseMode.HTML
                )
                return

            # If fuzzy match returned multiple operators, show suggestions
            unique_operators = list(set(op["operator"] for op in operators_data))

            if len(unique_operators) > 1:
                # Show "Did you mean..." suggestions
                suggestions = "\n".join([
                    f"• <code>{op}</code>"
                    for op in unique_operators[:10]
                ])

                await update.message.reply_text(
                    f"🔍 Operator '{operator_name}' not found.\n\n"
                    f"<b>Did you mean:</b>\n{suggestions}\n\n"
                    f"Use /operator &lt;full name&gt; to query.",
                    parse_mode=ParseMode.HTML
                )
                return

            # Single fuzzy match - use it
            operator_name = unique_operators[0]
            logger.info(f"Using fuzzy match: {operator_name}")

        # Get the exact operator name
        exact_operator_name = operators_data[0]["operator"]
        logger.info(f"Found operator: {exact_operator_name}")

        # Send loading message
        loading_msg = await update.message.reply_text(
            f"⏳ Found operator: {exact_operator_name}. Resolving IPs...",
            parse_mode=ParseMode.HTML
        )

        # Get MNC-MCC pairs
        mnc_mcc_pairs = [(op["mnc"], op["mcc"]) for op in operators_data]

        # Get FQDNs
        fqdns = await db.get_fqdns_by_operator(exact_operator_name)

        if not fqdns:
            await loading_msg.delete()
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No FQDNs found for {exact_operator_name}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Resolve infrastructure
        infrastructure = get_operator_infrastructure(
            operator_name=exact_operator_name,
            fqdns=fqdns,
            mnc_mcc_pairs=mnc_mcc_pairs,
            max_workers=Config.DNS_CONCURRENT_WORKERS,
            timeout=Config.DNS_RESOLUTION_TIMEOUT
        )

        # Delete loading message
        await loading_msg.delete()

        if not infrastructure["active_fqdns"]:
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No active infrastructure found for {exact_operator_name}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Format and send response
        response = format_operator_response(
            operator_name=exact_operator_name,
            operator_data=infrastructure,
            max_fqdns=20  # Show more FQDNs for operator-specific query
        )

        await update.message.reply_text(
            response,
            parse_mode=ParseMode.HTML
        )

        # Log query
        await db.log_query(
            telegram_user_id=user.id,
            query_type="operator",
            query_value=operator_name,
            result_count=len(infrastructure["active_fqdns"])
        )

    except Exception as e:
        logger.error(f"Error in operator command: {e}", exc_info=True)
        await update.message.reply_text(
            format_error_message("db_error", "An error occurred while processing your request."),
            parse_mode=ParseMode.HTML
        )
