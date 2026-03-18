"""
Data cleansing and normalisation helpers for 3GPP MCC/MNC data.

This module is the single source of truth for input validation and
normalisation across all Python scanning scripts.

Public API
----------
validate_mcc_mnc(mcc_str, mnc_str)
    Parses and range-checks MCC/MNC strings.  Returns ``(mcc_int, mnc_int)``
    on success or raises ``ValueError`` with a descriptive message.

normalize_operator(name)
    Strips leading/trailing whitespace from an operator name.
    Returns ``"Unknown"`` for blank or None input.

normalize_entry(item)
    Applies ``validate_mcc_mnc`` and ``normalize_operator`` to a raw
    MCC-MNC list dict (as returned by the pbakondy JSON feed).
    Returns a normalised copy of the dict, or ``None`` if the entry
    contains invalid MCC/MNC data.
"""

from __future__ import annotations

import unicodedata


# ---------------------------------------------------------------------------
# MCC / MNC validation
# ---------------------------------------------------------------------------

#: Inclusive range for valid Mobile Country Codes.
MCC_MIN: int = 1
MCC_MAX: int = 999

#: Inclusive range for valid Mobile Network Codes.
MNC_MIN: int = 0
MNC_MAX: int = 999


def validate_mcc_mnc(mcc_str: str | None, mnc_str: str | None) -> tuple[int, int]:
    """Parse and range-check *mcc_str* and *mnc_str*.

    Parameters
    ----------
    mcc_str:
        Raw MCC string from the MCC-MNC JSON source (e.g. ``"310"``).
    mnc_str:
        Raw MNC string from the MCC-MNC JSON source (e.g. ``"260"``).

    Returns
    -------
    tuple[int, int]
        ``(mcc, mnc)`` as integers.

    Raises
    ------
    ValueError
        If either value is ``None``, empty, non-numeric, or outside its
        valid range.
    """
    if mcc_str is None or str(mcc_str).strip() == "":
        raise ValueError("MCC is empty or None")
    if mnc_str is None or str(mnc_str).strip() == "":
        raise ValueError("MNC is empty or None")

    mcc_s = str(mcc_str).strip()
    mnc_s = str(mnc_str).strip()

    try:
        mcc = int(mcc_s)
    except ValueError:
        raise ValueError(f"MCC {mcc_s!r} is not a valid integer")

    try:
        mnc = int(mnc_s)
    except ValueError:
        raise ValueError(f"MNC {mnc_s!r} is not a valid integer")

    if mcc < MCC_MIN or mcc > MCC_MAX:
        raise ValueError(f"MCC {mcc} is out of range [{MCC_MIN}, {MCC_MAX}]")

    if mnc < MNC_MIN or mnc > MNC_MAX:
        raise ValueError(f"MNC {mnc} is out of range [{MNC_MIN}, {MNC_MAX}]")

    return mcc, mnc


# ---------------------------------------------------------------------------
# Operator name normalisation
# ---------------------------------------------------------------------------

def _normalize_text(value: str | None) -> str:
    """Strip whitespace and NFC-normalise *value*.

    Returns the empty string when *value* is ``None`` or whitespace-only.
    This is the shared implementation used by :func:`normalize_operator`.
    """
    if value is None:
        return ""
    return unicodedata.normalize("NFC", str(value)).strip()


def normalize_operator(name: str | None) -> str:
    """Return a normalised operator name.

    - Strips leading / trailing ASCII and Unicode whitespace.
    - Normalises Unicode to NFC form (canonical decomposition, canonical
      composition) so that visually identical strings compare equal.
    - Returns ``"Unknown"`` when *name* is ``None``, empty, or
      whitespace-only.

    Parameters
    ----------
    name:
        Raw operator name string (may contain extra whitespace or be ``None``).
    """
    cleaned = _normalize_text(name)
    return cleaned if cleaned else "Unknown"


# ---------------------------------------------------------------------------
# Combined entry normalisation
# ---------------------------------------------------------------------------

def normalize_entry(item: dict) -> dict | None:
    """Validate and normalise a single MCC-MNC list entry.

    Applies :func:`validate_mcc_mnc` and :func:`normalize_operator` to the
    raw dict produced by the pbakondy JSON feed.  Returns a *new* dict with
    cleaned values so the caller's original dict is not mutated.

    Returns ``None`` when the entry contains invalid MCC/MNC data so that
    callers can skip it without catching exceptions.

    Parameters
    ----------
    item:
        A dict with at least ``"mcc"`` and ``"mnc"`` keys.

    Returns
    -------
    dict | None
        Normalised copy, or ``None`` for invalid entries.
    """
    try:
        mcc, mnc = validate_mcc_mnc(item.get("mcc"), item.get("mnc"))
    except (ValueError, TypeError):
        return None

    return {
        **item,
        "mcc":         str(mcc),
        "mnc":         str(mnc),
        "operator":    normalize_operator(item.get("operator", "")),
        "countryName": _normalize_text(item.get("countryName", "")) or "Unknown",
        "countryCode": str(item.get("countryCode") or "").strip().upper(),
    }
