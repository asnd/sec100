"""
MSISDN (phone number) query handler for /phone command.

Parses international phone numbers and queries operators for the detected country.
"""

from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from services.database import Database
from services.msisdn_parser import parse_phone_number
from services.ip_resolver import get_operator_infrastructure
from services.formatter import format_phone_response, format_error_message
from config import Config
from utils.logger import get_logger

logger = get_logger("handlers.msisdn")


async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle /phone command.

    Usage: /phone <number>
    Example: /phone +43-660-1234567

    Args:
        update: Telegram update
        context: Bot context
    """
    user = update.effective_user
    logger.info(f"Phone command from user {user.id} (@{user.username})")

    # Parse command arguments
    if not context.args:
        await update.message.reply_text(
            format_error_message(
                "invalid_input",
                "Please provide a phone number in international format.\n"
                "Example: /phone +43-660-1234567"
            ),
            parse_mode=ParseMode.HTML
        )
        return

    phone_number = "".join(context.args)
    logger.info(f"Parsing phone number: {phone_number}")

    # Send "typing" action
    await update.message.chat.send_action("typing")

    try:
        # Parse phone number
        parsed = parse_phone_number(phone_number)

        if not parsed["valid"]:
            await update.message.reply_text(
                format_error_message(
                    "phone_invalid",
                    f"Error: {parsed['error']}\n\n"
                    f"Please use international format with country code.\n"
                    f"Examples: +43-660-1234567, +1-555-1234567"
                ),
                parse_mode=ParseMode.HTML
            )
            return

        country_code_e164 = parsed["country_code"]
        country_iso = parsed["country"]
        formatted_phone = parsed["formatted"]

        logger.info(
            f"Parsed phone: {formatted_phone}, "
            f"Country code: +{country_code_e164}, "
            f"ISO: {country_iso}"
        )

        # Initialize database
        db = Database(Config.DB_PATH)

        # Get MCC codes for this phone country code
        mcc_data = await db.get_mccs_by_phone_code(country_code_e164)

        if not mcc_data:
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No MCC mapping found for phone code +{country_code_e164} ({country_iso}).\n\n"
                    f"This country may not have mobile operators in our database."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Extract unique country info
        country_name = mcc_data[0]["country_name"]
        country_code = mcc_data[0]["country_code"]
        mcc_list = [item["mcc"] for item in mcc_data]

        logger.info(
            f"Found country: {country_name} ({country_code}), "
            f"MCCs: {mcc_list}"
        )

        # Handle multiple countries for one phone code (e.g., +1 = USA, Canada, etc.)
        if len(set(item["country_name"] for item in mcc_data)) > 1:
            countries_str = ", ".join(set(item["country_name"] for item in mcc_data))
            await update.message.reply_text(
                f"📱 Phone code +{country_code_e164} covers multiple countries:\n"
                f"{countries_str}\n\n"
                f"Showing results for all countries...",
                parse_mode=ParseMode.HTML
            )

        # Get operators for all MCCs
        all_operators_data = []
        for mcc in mcc_list:
            operators_data = await db.get_operators_by_mcc(int(mcc))
            all_operators_data.extend(operators_data)

        if not all_operators_data:
            await update.message.reply_text(
                format_error_message(
                    "no_results",
                    f"No operators found for {country_name}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Send loading message
        loading_msg = await update.message.reply_text(
            f"⏳ Found {len(all_operators_data)} operator(s) for {country_name}. Resolving IPs...",
            parse_mode=ParseMode.HTML
        )

        # Group operators by name and get infrastructure
        operators_dict = {}
        for op_data in all_operators_data:
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
                    f"No active infrastructure found for {country_name}."
                ),
                parse_mode=ParseMode.HTML
            )
            return

        # Format and send response
        response = format_phone_response(
            phone_number=formatted_phone,
            country_name=country_name,
            country_code=country_code,
            mcc_list=mcc_list,
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
            query_type="msisdn",
            query_value=formatted_phone,
            result_count=len(operator_results)
        )

    except Exception as e:
        logger.error(f"Error in phone command: {e}", exc_info=True)
        await update.message.reply_text(
            format_error_message("db_error", "An error occurred while processing your request."),
            parse_mode=ParseMode.HTML
        )
