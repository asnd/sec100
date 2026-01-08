"""
Country query handler for /country command.

Allows users to search for operators by country name.
"""

from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from services.database import Database
from services.ip_resolver import get_operator_infrastructure
from services.formatter import format_country_response, format_error_message
from config import Config
from utils.logger import get_logger

logger = get_logger("handlers.country")


async def country_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /country command.

    Usage: /country <name>
    Example: /country Austria

    Args:
        update: Telegram update
        context: Bot context
    """
    user = update.effective_user
    logger.info(f"Country command from user {user.id} (@{user.username})")

    # Parse command arguments
    if not context.args:
        await update.message.reply_text(
            format_error_message(
                "invalid_input",
                "Please provide a country name.\nExample: /country Austria"
            ),
            parse_mode=ParseMode.HTML
        )
        return

    country_name = " ".join(context.args)
    logger.info(f"Searching for country: {country_name}")

    # Send "typing" action
    await update.message.chat.send_action("typing")

    try:
        # Initialize database
        db = Database(Config.DB_PATH)

        # Search for matching countries
        countries = await db.get_countries_by_name(country_name, limit=5)

        if not countries:
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No country found matching: {country_name}\n"
                    f"Try using the full country name or ISO code."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # If multiple countries match, show them
        if len(countries) > 1:
            country_list = "\n".join([
                f"• {c['country_name']} ({c['country_code']}) - MCC: {c['mcc']}"
                for c in countries
            ])
            await update.message.reply_text(
                f"🔍 Multiple countries found:\n\n{country_list}\n\n"
                f"Please be more specific.",
                parse_mode=ParseMode.HTML
            )
            return

        # Get the matched country
        country = countries[0]
        country_name_matched = country["country_name"]
        country_code = country["country_code"]
        mcc = country["mcc"]

        logger.info(f"Found country: {country_name_matched} ({country_code}), MCC: {mcc}")

        # Get operators for this country
        operators_data = await db.get_operators_by_mcc(int(mcc))

        if not operators_data:
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No operators found for {country_name_matched}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Send loading message for IP resolution
        loading_msg = await update.message.reply_text(
            f"⏳ Found {len(operators_data)} operator(s). Resolving IPs...",
            parse_mode=ParseMode.HTML
        )

        # Group operators by name and get infrastructure
        operators_dict = {}
        for op_data in operators_data:
            op_name = op_data["operator"]
            if op_name not in operators_dict:
                operators_dict[op_name] = []
            operators_dict[op_name].append((op_data["mnc"], op_data["mcc"]))

        # Resolve infrastructure for each operator
        operator_results = []
        for op_name, mnc_mcc_pairs in operators_dict.items():
            # Get FQDNs
            fqdns = await db.get_fqdns_by_operator(op_name)

            if fqdns:
                # Resolve IPs
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
                    f"No active infrastructure found for {country_name_matched}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Format and send response
        response = format_country_response(
            country_name=country_name_matched,
            country_code=country_code,
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
            query_type="country",
            query_value=country_name,
            result_count=len(operator_results)
        )

    except Exception as e:
        logger.error(f"Error in country command: {e}", exc_info=True)
        await update.message.reply_text(
            format_error_message("db_error", "An error occurred while processing your request."),
            parse_mode=ParseMode.HTML
        )
