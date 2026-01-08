"""
Response formatter for Telegram messages.

Handles formatting query results as Telegram-compatible Markdown with
pagination, truncation, and appropriate visual hierarchy.
"""

from typing import List, Dict
import html


def escape_markdown(text: str) -> str:
    """
    Escape special characters for Telegram MarkdownV2.

    Args:
        text: Text to escape

    Returns:
        Escaped text safe for Telegram MarkdownV2
    """
    # For simplicity, we'll use HTML mode instead of MarkdownV2
    # as it's easier to work with
    return html.escape(str(text))


def format_operator_result(
    operator_data: Dict,
    max_fqdns: int = 10,
    show_ips: bool = True
) -> str:
    """
    Format a single operator's infrastructure data.

    Args:
        operator_data: Dict with keys: operator, mnc_mcc_pairs, active_fqdns
        max_fqdns: Maximum number of FQDNs to show
        show_ips: Whether to show resolved IPs

    Returns:
        Formatted string for Telegram
    """
    lines = []

    # Operator name
    operator = escape_markdown(operator_data["operator"])
    lines.append(f"<b>{operator}</b>")

    # MNC/MCC pairs
    mnc_mcc_pairs = operator_data.get("mnc_mcc_pairs", [])
    if mnc_mcc_pairs:
        mnc_str = ", ".join(str(mnc) for mnc, _ in mnc_mcc_pairs)
        mcc_str = ", ".join(str(mcc) for _, mcc in set((mcc for _, mcc in mnc_mcc_pairs)))
        lines.append(f"   • MNC: {mnc_str} | MCC: {mcc_str}")

    # FQDNs
    active_fqdns = operator_data.get("active_fqdns", [])
    total_fqdns = operator_data.get("total_fqdns", len(active_fqdns))

    if not active_fqdns:
        lines.append(f"   • No active FQDNs found")
    else:
        lines.append(f"   • Active FQDNs: {len(active_fqdns)}/{total_fqdns}")
        lines.append("")

        # Show FQDNs (limited)
        shown = 0
        for fqdn_data in active_fqdns:
            if shown >= max_fqdns:
                remaining = len(active_fqdns) - shown
                lines.append(f"   ... and {remaining} more")
                break

            fqdn = escape_markdown(fqdn_data["fqdn"])
            lines.append(f"   📍 <code>{fqdn}</code>")

            if show_ips and fqdn_data.get("ips"):
                ips_str = ", ".join(escape_markdown(ip) for ip in fqdn_data["ips"])
                lines.append(f"      → {ips_str}")

            shown += 1

    return "\n".join(lines)


def format_country_response(
    country_name: str,
    country_code: str,
    mcc: str,
    operators: List[Dict],
    page: int = 1,
    total_pages: int = 1,
    max_operators_per_page: int = 5,
    max_fqdns_per_operator: int = 10
) -> str:
    """
    Format a country query response.

    Args:
        country_name: Country name
        country_code: ISO country code
        mcc: Mobile Country Code
        operators: List of operator infrastructure dicts
        page: Current page number
        total_pages: Total number of pages
        max_operators_per_page: Max operators to show per page
        max_fqdns_per_operator: Max FQDNs to show per operator

    Returns:
        Formatted Telegram message
    """
    lines = []

    # Header
    lines.append(f"🌍 <b>Country:</b> {escape_markdown(country_name)} ({escape_markdown(country_code)})")
    lines.append(f"📡 <b>MCC:</b> {escape_markdown(mcc)}")
    lines.append("")

    if not operators:
        lines.append("❌ No operators found with active infrastructure.")
        return "\n".join(lines)

    # Operator count
    lines.append(f"Found {len(operators)} operator(s):")
    lines.append("")

    # Show operators for this page
    start_idx = (page - 1) * max_operators_per_page
    end_idx = start_idx + max_operators_per_page
    page_operators = operators[start_idx:end_idx]

    for idx, op_data in enumerate(page_operators, start=start_idx + 1):
        # Number emoji
        number_emoji = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"][min(idx - 1, 9)]
        lines.append(number_emoji)

        # Operator details
        op_text = format_operator_result(op_data, max_fqdns_per_operator, show_ips=True)
        lines.append(op_text)
        lines.append("")

    # Pagination info
    if total_pages > 1:
        lines.append(f"📄 Page {page} of {total_pages}")

    return "\n".join(lines)


def format_mcc_response(
    mcc: int,
    operators: List[Dict],
    page: int = 1,
    total_pages: int = 1,
    max_operators_per_page: int = 5,
    max_fqdns_per_operator: int = 10
) -> str:
    """
    Format an MCC query response.

    Args:
        mcc: Mobile Country Code
        operators: List of operator infrastructure dicts
        page: Current page number
        total_pages: Total number of pages
        max_operators_per_page: Max operators per page
        max_fqdns_per_operator: Max FQDNs per operator

    Returns:
        Formatted Telegram message
    """
    lines = []

    # Header
    lines.append(f"📡 <b>MCC:</b> {mcc}")
    lines.append("")

    if not operators:
        lines.append(f"❌ No operators found for MCC {mcc}.")
        return "\n".join(lines)

    lines.append(f"Found {len(operators)} operator(s):")
    lines.append("")

    # Show operators for this page
    start_idx = (page - 1) * max_operators_per_page
    end_idx = start_idx + max_operators_per_page
    page_operators = operators[start_idx:end_idx]

    for idx, op_data in enumerate(page_operators, start=start_idx + 1):
        number_emoji = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"][min(idx - 1, 9)]
        lines.append(number_emoji)
        lines.append(format_operator_result(op_data, max_fqdns_per_operator, show_ips=True))
        lines.append("")

    # Pagination
    if total_pages > 1:
        lines.append(f"📄 Page {page} of {total_pages}")

    return "\n".join(lines)


def format_operator_response(
    operator_name: str,
    operator_data: Dict,
    max_fqdns: int = 20
) -> str:
    """
    Format an operator query response.

    Args:
        operator_name: Operator name
        operator_data: Operator infrastructure dict
        max_fqdns: Max FQDNs to show

    Returns:
        Formatted Telegram message
    """
    lines = []

    # Header
    lines.append(f"📱 <b>Operator:</b> {escape_markdown(operator_name)}")
    lines.append("")

    # Operator details
    lines.append(format_operator_result(operator_data, max_fqdns, show_ips=True))

    return "\n".join(lines)


def format_phone_response(
    phone_number: str,
    country_name: str,
    country_code: str,
    mcc_list: List[str],
    operators: List[Dict],
    page: int = 1,
    total_pages: int = 1,
    max_operators_per_page: int = 5,
    max_fqdns_per_operator: int = 10
) -> str:
    """
    Format an MSISDN query response.

    Args:
        phone_number: Formatted phone number
        country_name: Country name
        country_code: ISO country code
        mcc_list: List of MCC codes for this country
        operators: List of operator infrastructure dicts
        page: Current page
        total_pages: Total pages
        max_operators_per_page: Max operators per page
        max_fqdns_per_operator: Max FQDNs per operator

    Returns:
        Formatted Telegram message
    """
    lines = []

    # Header
    lines.append(f"📱 <b>MSISDN Analysis</b>")
    lines.append("")
    lines.append(f"Phone: <code>{escape_markdown(phone_number)}</code>")
    lines.append(f"Country: {escape_markdown(country_name)} ({escape_markdown(country_code)})")
    lines.append(f"MCC: {', '.join(escape_markdown(m) for m in mcc_list)}")
    lines.append("")

    if not operators:
        lines.append(f"❌ No operators found for {country_name}.")
        return "\n".join(lines)

    lines.append(f"🔍 Found {len(operators)} operator(s):")
    lines.append("")

    # Show operators
    start_idx = (page - 1) * max_operators_per_page
    end_idx = start_idx + max_operators_per_page
    page_operators = operators[start_idx:end_idx]

    for idx, op_data in enumerate(page_operators, start=start_idx + 1):
        number_emoji = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"][min(idx - 1, 9)]
        lines.append(number_emoji)
        lines.append(format_operator_result(op_data, max_fqdns_per_operator, show_ips=True))
        lines.append("")

    # Pagination
    if total_pages > 1:
        lines.append(f"📄 Page {page} of {total_pages}")

    return "\n".join(lines)


def format_error_message(error_type: str, details: str = "") -> str:
    """
    Format an error message.

    Args:
        error_type: Type of error
        details: Additional details

    Returns:
        Formatted error message
    """
    messages = {
        "invalid_input": "❌ Invalid input. Please check your command syntax.",
        "no_results": "❌ No results found.",
        "db_error": "⚠️ Database error. Please try again later.",
        "rate_limit": "⏱️ Rate limit exceeded. Please wait before trying again.",
        "phone_invalid": "❌ Invalid phone number. Please use international format (e.g., +43-660-1234567).",
    }

    message = messages.get(error_type, "❌ An error occurred.")

    if details:
        message += f"\n\n{escape_markdown(details)}"

    return message


def format_help_message() -> str:
    """
    Format the help/command reference message.

    Returns:
        Formatted help message
    """
    return """<b>3GPP Network Query Bot</b>

Query 3GPP public domain infrastructure for mobile operators worldwide.

<b>Commands:</b>

/start - Show welcome message
/help - Show this help message

<b>Query Commands:</b>

/country &lt;name&gt; - Search by country
   Example: <code>/country Austria</code>

/mcc &lt;code&gt; - Query by Mobile Country Code
   Example: <code>/mcc 232</code>

/mnc &lt;mnc&gt; &lt;mcc&gt; - Query by MNC+MCC
   Example: <code>/mnc 1 232</code>

/phone &lt;number&gt; - Parse phone number (MSISDN)
   Example: <code>/phone +43-660-1234567</code>

/operator &lt;name&gt; - Search by operator name
   Example: <code>/operator Vodafone</code>

<b>About:</b>
This bot queries discovered 3GPP network subdomains (ePDG, IMS, BSF, etc.) and resolves them to IP addresses in real-time.

Use responsibly for authorized security research and educational purposes only."""


def format_welcome_message() -> str:
    """
    Format the welcome message for /start command.

    Returns:
        Formatted welcome message
    """
    return """👋 <b>Welcome to 3GPP Network Query Bot!</b>

I can help you discover and analyze 3GPP mobile network infrastructure worldwide.

<b>Quick Start:</b>
• Try <code>/country Austria</code>
• Or <code>/phone +43-660-1234567</code>
• Or <code>/operator Vodafone</code>

Use /help to see all available commands.

🔒 <b>Security Notice:</b> This tool is for authorized security research and educational purposes only."""
