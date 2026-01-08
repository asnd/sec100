"""
MSISDN (phone number) parsing service.

Uses Google's libphonenumber library to parse international phone numbers
and extract country codes for MCC lookup.
"""

import phonenumbers
from phonenumbers import NumberParseException
from typing import Dict, Optional


def parse_phone_number(phone_number: str) -> Dict:
    """
    Parse an international phone number and extract details.

    Args:
        phone_number: Phone number in international format (e.g., +43-660-1234567)

    Returns:
        Dictionary with keys:
        - valid: bool - Whether the number is valid
        - country_code: str - E.164 country code (e.g., "43")
        - country: str - ISO 3166-1 alpha-2 country code (e.g., "AT")
        - national_number: str - National significant number
        - formatted: str - Internationally formatted number
        - error: str - Error message if invalid

    Example:
        >>> parse_phone_number("+43-660-1234567")
        {
            "valid": True,
            "country_code": "43",
            "country": "AT",
            "national_number": "6601234567",
            "formatted": "+43 660 1234567",
            "error": None
        }
    """
    try:
        # Parse the phone number
        parsed = phonenumbers.parse(phone_number, None)

        # Validate the number
        is_valid = phonenumbers.is_valid_number(parsed)

        # Extract details
        country_code = str(parsed.country_code)
        country = phonenumbers.region_code_for_number(parsed)
        national_number = str(parsed.national_number)

        # Format for display
        formatted = phonenumbers.format_number(
            parsed,
            phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )

        return {
            "valid": is_valid,
            "country_code": country_code,
            "country": country,
            "national_number": national_number,
            "formatted": formatted,
            "error": None
        }

    except NumberParseException as e:
        return {
            "valid": False,
            "country_code": None,
            "country": None,
            "national_number": None,
            "formatted": None,
            "error": str(e)
        }
    except Exception as e:
        return {
            "valid": False,
            "country_code": None,
            "country": None,
            "national_number": None,
            "formatted": None,
            "error": f"Unexpected error: {str(e)}"
        }


def extract_country_code(phone_number: str) -> Optional[str]:
    """
    Extract just the E.164 country code from a phone number.

    Args:
        phone_number: Phone number in international format

    Returns:
        Country code string (e.g., "43") or None if parsing fails

    Example:
        >>> extract_country_code("+43-660-1234567")
        "43"
        >>> extract_country_code("+1-555-1234567")
        "1"
    """
    result = parse_phone_number(phone_number)
    return result["country_code"] if result["valid"] else None


def get_phone_number_region(phone_number: str) -> Optional[str]:
    """
    Get the ISO country code for a phone number.

    Args:
        phone_number: Phone number in international format

    Returns:
        ISO 3166-1 alpha-2 country code (e.g., "AT") or None

    Example:
        >>> get_phone_number_region("+43-660-1234567")
        "AT"
    """
    result = parse_phone_number(phone_number)
    return result["country"] if result["valid"] else None


def is_valid_phone_number(phone_number: str) -> bool:
    """
    Check if a phone number is valid.

    Args:
        phone_number: Phone number to validate

    Returns:
        True if valid, False otherwise

    Example:
        >>> is_valid_phone_number("+43-660-1234567")
        True
        >>> is_valid_phone_number("invalid")
        False
    """
    result = parse_phone_number(phone_number)
    return result["valid"]


def format_phone_number(phone_number: str) -> Optional[str]:
    """
    Format a phone number in international format.

    Args:
        phone_number: Phone number to format

    Returns:
        Formatted phone number or None if invalid

    Example:
        >>> format_phone_number("+436601234567")
        "+43 660 1234567"
    """
    result = parse_phone_number(phone_number)
    return result["formatted"] if result["valid"] else None
