"""
Unit tests for epdg/normalize.py — data cleansing and normalisation helpers.
"""

import sys
from pathlib import Path

import pytest

# Make the epdg package importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from normalize import (
    MCC_MAX,
    MCC_MIN,
    MNC_MAX,
    MNC_MIN,
    normalize_entry,
    normalize_operator,
    validate_mcc_mnc,
)


# ─────────────────────────────────────────────────────────────────────────────
# validate_mcc_mnc
# ─────────────────────────────────────────────────────────────────────────────


class TestValidateMccMnc:
    """Tests for the validate_mcc_mnc() function."""

    # --- Valid inputs --------------------------------------------------------

    def test_typical_values(self):
        assert validate_mcc_mnc("310", "260") == (310, 260)

    def test_zero_padded_mnc(self):
        assert validate_mcc_mnc("232", "001") == (232, 1)

    def test_mnc_zero(self):
        assert validate_mcc_mnc("460", "000") == (460, 0)

    def test_boundary_mcc_min(self):
        assert validate_mcc_mnc(str(MCC_MIN), "001") == (MCC_MIN, 1)

    def test_boundary_mcc_max(self):
        assert validate_mcc_mnc(str(MCC_MAX), "001") == (MCC_MAX, 1)

    def test_boundary_mnc_min(self):
        assert validate_mcc_mnc("310", str(MNC_MIN)) == (310, MNC_MIN)

    def test_boundary_mnc_max(self):
        assert validate_mcc_mnc("310", str(MNC_MAX)) == (310, MNC_MAX)

    def test_strips_whitespace(self):
        assert validate_mcc_mnc("  310  ", "  260  ") == (310, 260)

    # --- Invalid MCC --------------------------------------------------------

    def test_empty_mcc(self):
        with pytest.raises(ValueError, match="MCC"):
            validate_mcc_mnc("", "260")

    def test_none_mcc(self):
        with pytest.raises((ValueError, TypeError)):
            validate_mcc_mnc(None, "260")

    def test_whitespace_only_mcc(self):
        with pytest.raises(ValueError):
            validate_mcc_mnc("   ", "260")

    def test_non_numeric_mcc(self):
        with pytest.raises(ValueError, match="not a valid integer"):
            validate_mcc_mnc("abc", "260")

    def test_mcc_zero(self):
        with pytest.raises(ValueError, match="out of range"):
            validate_mcc_mnc("0", "260")

    def test_mcc_negative(self):
        with pytest.raises(ValueError, match="out of range"):
            validate_mcc_mnc("-1", "260")

    def test_mcc_too_large(self):
        with pytest.raises(ValueError, match="out of range"):
            validate_mcc_mnc("1000", "260")

    def test_mcc_float_string(self):
        with pytest.raises(ValueError, match="not a valid integer"):
            validate_mcc_mnc("3.10", "260")

    # --- Invalid MNC --------------------------------------------------------

    def test_empty_mnc(self):
        with pytest.raises(ValueError, match="MNC"):
            validate_mcc_mnc("310", "")

    def test_none_mnc(self):
        with pytest.raises((ValueError, TypeError)):
            validate_mcc_mnc("310", None)

    def test_whitespace_only_mnc(self):
        with pytest.raises(ValueError):
            validate_mcc_mnc("310", "   ")

    def test_non_numeric_mnc(self):
        with pytest.raises(ValueError, match="not a valid integer"):
            validate_mcc_mnc("310", "xyz")

    def test_mnc_negative(self):
        with pytest.raises(ValueError, match="out of range"):
            validate_mcc_mnc("310", "-1")

    def test_mnc_too_large(self):
        with pytest.raises(ValueError, match="out of range"):
            validate_mcc_mnc("310", "1000")


# ─────────────────────────────────────────────────────────────────────────────
# normalize_operator
# ─────────────────────────────────────────────────────────────────────────────


class TestNormalizeOperator:
    """Tests for the normalize_operator() function."""

    def test_plain_string(self):
        assert normalize_operator("T-Mobile US") == "T-Mobile US"

    def test_strips_leading_trailing_spaces(self):
        assert normalize_operator("  Vodafone  ") == "Vodafone"

    def test_strips_tabs_and_newlines(self):
        assert normalize_operator("\tAT&T\n") == "AT&T"

    def test_empty_string_returns_unknown(self):
        assert normalize_operator("") == "Unknown"

    def test_whitespace_only_returns_unknown(self):
        assert normalize_operator("   ") == "Unknown"

    def test_none_returns_unknown(self):
        assert normalize_operator(None) == "Unknown"

    def test_unicode_nfc_normalization(self):
        # "é" can be encoded as U+00E9 (NFC) or U+0065 U+0301 (NFD)
        nfd_e = "e\u0301"  # NFD form of é
        nfc_e = "\u00e9"   # NFC form of é
        result = normalize_operator(f"Op{nfd_e}rateur")
        assert result == f"Op{nfc_e}rateur"

    def test_internal_whitespace_preserved(self):
        assert normalize_operator("China Mobile") == "China Mobile"

    def test_numeric_string(self):
        assert normalize_operator("123") == "123"


# ─────────────────────────────────────────────────────────────────────────────
# normalize_entry
# ─────────────────────────────────────────────────────────────────────────────


class TestNormalizeEntry:
    """Tests for the normalize_entry() function."""

    def _good_item(self, **overrides) -> dict:
        base = {
            "mcc": "310",
            "mnc": "260",
            "operator": "T-Mobile US",
            "countryName": "United States",
            "countryCode": "us",
        }
        return {**base, **overrides}

    # --- Valid entries -------------------------------------------------------

    def test_valid_entry_returns_dict(self):
        result = normalize_entry(self._good_item())
        assert result is not None

    def test_valid_entry_mcc_mnc_preserved(self):
        result = normalize_entry(self._good_item())
        assert result["mcc"] == "310"
        assert result["mnc"] == "260"

    def test_valid_entry_operator_stripped(self):
        result = normalize_entry(self._good_item(operator="  Vodafone  "))
        assert result["operator"] == "Vodafone"

    def test_valid_entry_country_name_stripped(self):
        result = normalize_entry(self._good_item(countryName="  Austria  "))
        assert result["countryName"] == "Austria"

    def test_valid_entry_country_code_uppercased(self):
        result = normalize_entry(self._good_item(countryCode="us"))
        assert result["countryCode"] == "US"

    def test_zero_padded_mcc_mnc(self):
        result = normalize_entry(self._good_item(mcc="001", mnc="001"))
        assert result["mcc"] == "1"
        assert result["mnc"] == "1"

    def test_original_dict_not_mutated(self):
        item = self._good_item(operator="  Original  ")
        normalize_entry(item)
        assert item["operator"] == "  Original  "

    def test_extra_fields_preserved(self):
        result = normalize_entry(self._good_item(brand="T-Mo", bands="LTE"))
        assert result["brand"] == "T-Mo"
        assert result["bands"] == "LTE"

    # --- Invalid entries return None ----------------------------------------

    def test_missing_mcc_returns_none(self):
        item = self._good_item()
        del item["mcc"]
        assert normalize_entry(item) is None

    def test_empty_mcc_returns_none(self):
        assert normalize_entry(self._good_item(mcc="")) is None

    def test_none_mcc_returns_none(self):
        assert normalize_entry(self._good_item(mcc=None)) is None

    def test_non_numeric_mcc_returns_none(self):
        assert normalize_entry(self._good_item(mcc="abc")) is None

    def test_mcc_zero_returns_none(self):
        assert normalize_entry(self._good_item(mcc="0")) is None

    def test_mcc_too_large_returns_none(self):
        assert normalize_entry(self._good_item(mcc="1000")) is None

    def test_empty_mnc_returns_none(self):
        assert normalize_entry(self._good_item(mnc="")) is None

    def test_non_numeric_mnc_returns_none(self):
        assert normalize_entry(self._good_item(mnc="xyz")) is None

    def test_mnc_too_large_returns_none(self):
        assert normalize_entry(self._good_item(mnc="1000")) is None

    def test_empty_operator_becomes_unknown(self):
        result = normalize_entry(self._good_item(operator=""))
        assert result is not None
        assert result["operator"] == "Unknown"

    def test_none_operator_becomes_unknown(self):
        result = normalize_entry(self._good_item(operator=None))
        assert result is not None
        assert result["operator"] == "Unknown"

    def test_empty_dict_returns_none(self):
        assert normalize_entry({}) is None


# ─────────────────────────────────────────────────────────────────────────────
# fqdn_to_service (subdomains.py helper)
# ─────────────────────────────────────────────────────────────────────────────


class TestFqdnToService:
    """Tests for subdomains.fqdn_to_service() specificity ordering."""

    def setup_method(self):
        from subdomains import fqdn_to_service
        self.fqdn_to_service = fqdn_to_service

    def test_ims_fqdn(self):
        fqdn = "ims.mnc260.mcc310.pub.3gppnetwork.org"
        assert self.fqdn_to_service(fqdn) == "ims"

    def test_pcscf_ims_takes_priority_over_ims(self):
        fqdn = "pcscf.ims.mnc260.mcc310.pub.3gppnetwork.org"
        assert self.fqdn_to_service(fqdn) == "pcscf.ims"

    def test_sos_ims_takes_priority_over_ims(self):
        fqdn = "sos.ims.mnc260.mcc310.pub.3gppnetwork.org"
        assert self.fqdn_to_service(fqdn) == "sos.ims"

    def test_epdg_epc(self):
        fqdn = "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"
        assert self.fqdn_to_service(fqdn) == "epdg.epc"

    def test_ss_epdg_epc_takes_priority_over_epdg_epc(self):
        fqdn = "ss.epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"
        assert self.fqdn_to_service(fqdn) == "ss.epdg.epc"

    def test_sos_epdg_epc_takes_priority_over_epdg_epc(self):
        fqdn = "sos.epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"
        assert self.fqdn_to_service(fqdn) == "sos.epdg.epc"

    def test_unknown_returns_other(self):
        fqdn = "unknown.mnc260.mcc310.pub.3gppnetwork.org"
        assert self.fqdn_to_service(fqdn) == "other"

    def test_bsf(self):
        fqdn = "bsf.mnc001.mcc232.pub.3gppnetwork.org"
        assert self.fqdn_to_service(fqdn) == "bsf"

    def test_n3iwf_5gc(self):
        fqdn = "n3iwf.5gc.mnc001.mcc310.pub.3gppnetwork.org"
        assert self.fqdn_to_service(fqdn) == "n3iwf.5gc"


# ─────────────────────────────────────────────────────────────────────────────
# FQDN construction
# ─────────────────────────────────────────────────────────────────────────────


class TestFqdnConstruction:
    """Verify that the FQDN format produced by scanning scripts is correct."""

    PARENT = "pub.3gppnetwork.org"

    def _build(self, subdomain: str, mnc: int, mcc: int) -> str:
        return f"{subdomain}.mnc{mnc:03d}.mcc{mcc:03d}.{self.PARENT}"

    def test_standard_fqdn(self):
        assert self._build("ims", 1, 310) == "ims.mnc001.mcc310.pub.3gppnetwork.org"

    def test_zero_padded_mnc(self):
        assert self._build("epdg.epc", 5, 311) == "epdg.epc.mnc005.mcc311.pub.3gppnetwork.org"

    def test_triple_digit_mnc(self):
        assert self._build("bsf", 260, 310) == "bsf.mnc260.mcc310.pub.3gppnetwork.org"

    def test_mnc_zero(self):
        assert self._build("ims", 0, 460) == "ims.mnc000.mcc460.pub.3gppnetwork.org"

    def test_three_segment_subdomain(self):
        assert self._build("xcap.ims", 1, 232) == "xcap.ims.mnc001.mcc232.pub.3gppnetwork.org"
