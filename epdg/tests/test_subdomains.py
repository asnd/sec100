"""
Unit tests for epdg/subdomains.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from subdomains import (
    SUBDOMAIN_DEFS,
    SUBDOMAINS,
    SCORE_WEIGHTS,
    SERVICE_COLORS,
    NAPTR_PROBE_SERVICES,
    fqdn_to_service,
    sql_case_when,
)

import pytest


# ── SUBDOMAIN_DEFS structure ──────────────────────────────────────────────────

REQUIRED_FIELDS = {"subdomain", "category", "label", "score"}


def test_subdomain_defs_is_nonempty():
    assert len(SUBDOMAIN_DEFS) > 0


@pytest.mark.parametrize("entry", SUBDOMAIN_DEFS)
def test_subdomain_def_has_required_fields(entry):
    for field in REQUIRED_FIELDS:
        assert field in entry, f"Missing field '{field}' in entry: {entry}"


@pytest.mark.parametrize("entry", SUBDOMAIN_DEFS)
def test_subdomain_def_types(entry):
    assert isinstance(entry["subdomain"], str) and entry["subdomain"], \
        "subdomain must be a non-empty string"
    assert isinstance(entry["category"], str) and entry["category"], \
        "category must be a non-empty string"
    assert isinstance(entry["label"], str) and entry["label"], \
        "label must be a non-empty string"
    assert isinstance(entry["score"], int) and entry["score"] >= 0, \
        "score must be a non-negative int"


@pytest.mark.parametrize("entry", SUBDOMAIN_DEFS)
def test_subdomain_def_has_color(entry):
    assert "color" in entry, f"Missing 'color' in entry: {entry}"
    assert isinstance(entry["color"], str) and entry["color"].startswith("#"), \
        f"color should be a hex string, got: {entry['color']}"


@pytest.mark.parametrize("entry", SUBDOMAIN_DEFS)
def test_subdomain_def_has_naptr_probe(entry):
    assert "naptr_probe" in entry, f"Missing 'naptr_probe' in entry: {entry}"
    assert isinstance(entry["naptr_probe"], bool), \
        f"naptr_probe must be bool, got: {type(entry['naptr_probe'])}"


def test_subdomain_defs_no_duplicate_subdomains():
    names = [d["subdomain"] for d in SUBDOMAIN_DEFS]
    assert len(names) == len(set(names)), \
        f"Duplicate subdomains found: {[n for n in names if names.count(n) > 1]}"


# ── Specificity ordering ──────────────────────────────────────────────────────

def test_ss_epdg_epc_before_epdg_epc():
    """More-specific 'ss.epdg.epc' must appear before generic 'epdg.epc'."""
    names = [d["subdomain"] for d in SUBDOMAIN_DEFS]
    assert names.index("ss.epdg.epc") < names.index("epdg.epc")


def test_sos_epdg_epc_before_epdg_epc():
    """More-specific 'sos.epdg.epc' must appear before generic 'epdg.epc'."""
    names = [d["subdomain"] for d in SUBDOMAIN_DEFS]
    assert names.index("sos.epdg.epc") < names.index("epdg.epc")


def test_sos_ims_before_ims():
    """More-specific 'sos.ims' must appear before generic 'ims'."""
    names = [d["subdomain"] for d in SUBDOMAIN_DEFS]
    assert names.index("sos.ims") < names.index("ims")


def test_pcscf_ims_before_ims():
    """More-specific 'pcscf.ims' must appear before generic 'ims'."""
    names = [d["subdomain"] for d in SUBDOMAIN_DEFS]
    assert names.index("pcscf.ims") < names.index("ims")


# ── SUBDOMAINS list ───────────────────────────────────────────────────────────

def test_subdomains_derived_from_defs():
    expected = [d["subdomain"] for d in SUBDOMAIN_DEFS]
    assert SUBDOMAINS == expected


def test_subdomains_contains_epdg_epc():
    assert "epdg.epc" in SUBDOMAINS


def test_subdomains_contains_ims():
    assert "ims" in SUBDOMAINS


def test_subdomains_contains_bsf():
    assert "bsf" in SUBDOMAINS


# ── SCORE_WEIGHTS ─────────────────────────────────────────────────────────────

def test_score_weights_only_positive_scores():
    """SCORE_WEIGHTS must only contain entries where score > 0."""
    for subdomain, (label, score, icon) in SCORE_WEIGHTS.items():
        assert score > 0, \
            f"SCORE_WEIGHTS entry '{subdomain}' has score={score}, expected > 0"


def test_score_weights_excludes_zero_score_entries():
    zero_score_subdomains = [d["subdomain"] for d in SUBDOMAIN_DEFS if d["score"] == 0]
    for subdomain in zero_score_subdomains:
        assert subdomain not in SCORE_WEIGHTS, \
            f"Zero-score subdomain '{subdomain}' should not be in SCORE_WEIGHTS"


def test_epdg_epc_score_at_least_15():
    assert "epdg.epc" in SCORE_WEIGHTS, "epdg.epc must be in SCORE_WEIGHTS"
    _label, score, _icon = SCORE_WEIGHTS["epdg.epc"]
    assert score >= 15, f"epdg.epc score should be >= 15, got {score}"


def test_score_weights_tuple_structure():
    for subdomain, value in SCORE_WEIGHTS.items():
        assert len(value) == 3, \
            f"SCORE_WEIGHTS['{subdomain}'] should be a 3-tuple (label, score, icon)"
        label, score, icon = value
        assert isinstance(label, str)
        assert isinstance(score, int)
        assert isinstance(icon, str)


# ── SERVICE_COLORS ────────────────────────────────────────────────────────────

def test_service_colors_contains_all_subdomains():
    for d in SUBDOMAIN_DEFS:
        assert d["subdomain"] in SERVICE_COLORS, \
            f"SERVICE_COLORS missing entry for '{d['subdomain']}'"


def test_service_colors_has_other_key():
    assert "other" in SERVICE_COLORS


def test_service_colors_other_is_hex():
    assert SERVICE_COLORS["other"].startswith("#")


# ── NAPTR_PROBE_SERVICES ──────────────────────────────────────────────────────

def test_naptr_probe_services_subset_of_subdomains():
    for svc in NAPTR_PROBE_SERVICES:
        assert svc in SUBDOMAINS, \
            f"NAPTR_PROBE_SERVICES entry '{svc}' not found in SUBDOMAINS"


def test_naptr_probe_services_matches_defs():
    expected = [d["subdomain"] for d in SUBDOMAIN_DEFS if d["naptr_probe"]]
    assert NAPTR_PROBE_SERVICES == expected


def test_epdg_epc_is_naptr_probe_service():
    assert "epdg.epc" in NAPTR_PROBE_SERVICES


# ── fqdn_to_service ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("fqdn,expected_service", [
    # epdg.epc variants
    ("epdg.epc.mnc001.mcc310.pub.3gppnetwork.org", "epdg.epc"),
    ("epdg.epc.mnc099.mcc234.pub.3gppnetwork.org", "epdg.epc"),
    # ims variants
    ("ims.mnc001.mcc310.pub.3gppnetwork.org", "ims"),
    ("ims.mnc042.mcc232.pub.3gppnetwork.org", "ims"),
    # bsf
    ("bsf.mnc001.mcc310.pub.3gppnetwork.org", "bsf"),
    # gan
    ("gan.mnc001.mcc310.pub.3gppnetwork.org", "gan"),
    # xcap.ims
    ("xcap.ims.mnc001.mcc310.pub.3gppnetwork.org", "xcap.ims"),
    # pcscf.ims
    ("pcscf.ims.mnc001.mcc310.pub.3gppnetwork.org", "pcscf.ims"),
    # n3iwf.5gc
    ("n3iwf.5gc.mnc001.mcc310.pub.3gppnetwork.org", "n3iwf.5gc"),
    # rcs
    ("rcs.mnc001.mcc310.pub.3gppnetwork.org", "rcs"),
    # unknown/other
    ("unknown.mnc001.mcc310.pub.3gppnetwork.org", "other"),
    ("foo.bar.baz.example.com", "other"),
])
def test_fqdn_to_service_known_fqdns(fqdn, expected_service):
    assert fqdn_to_service(fqdn) == expected_service


def test_fqdn_to_service_specificity_ss_epdg_epc():
    """'ss.epdg.epc.*' should map to 'ss.epdg.epc', not 'epdg.epc'."""
    fqdn = "ss.epdg.epc.mnc001.mcc310.pub.3gppnetwork.org"
    result = fqdn_to_service(fqdn)
    assert result == "ss.epdg.epc", \
        f"Expected 'ss.epdg.epc' due to specificity, got '{result}'"


def test_fqdn_to_service_specificity_sos_epdg_epc():
    """'sos.epdg.epc.*' should map to 'sos.epdg.epc', not 'epdg.epc'."""
    fqdn = "sos.epdg.epc.mnc001.mcc310.pub.3gppnetwork.org"
    result = fqdn_to_service(fqdn)
    assert result == "sos.epdg.epc", \
        f"Expected 'sos.epdg.epc' due to specificity, got '{result}'"


def test_fqdn_to_service_specificity_sos_ims():
    """'sos.ims.*' should map to 'sos.ims', not 'ims'."""
    fqdn = "sos.ims.mnc001.mcc310.pub.3gppnetwork.org"
    result = fqdn_to_service(fqdn)
    assert result == "sos.ims", \
        f"Expected 'sos.ims' due to specificity, got '{result}'"


def test_fqdn_to_service_empty_string():
    assert fqdn_to_service("") == "other"


def test_fqdn_to_service_returns_string():
    result = fqdn_to_service("epdg.epc.mnc001.mcc310.pub.3gppnetwork.org")
    assert isinstance(result, str)


def test_fqdn_to_service_all_subdomains_recognized():
    """Every defined subdomain should be recognized when used as an FQDN prefix."""
    for subdomain in SUBDOMAINS:
        fqdn = f"{subdomain}.mnc001.mcc310.pub.3gppnetwork.org"
        result = fqdn_to_service(fqdn)
        assert result == subdomain, \
            f"fqdn_to_service('{fqdn}') returned '{result}', expected '{subdomain}'"


# ── sql_case_when ─────────────────────────────────────────────────────────────

def test_sql_case_when_starts_with_case():
    result = sql_case_when()
    assert result.strip().startswith("CASE"), \
        "sql_case_when() output should start with 'CASE'"


def test_sql_case_when_ends_with_end():
    result = sql_case_when()
    assert result.strip().endswith("END"), \
        "sql_case_when() output should end with 'END'"


def test_sql_case_when_contains_else_other():
    result = sql_case_when()
    assert "ELSE 'other'" in result


def test_sql_case_when_all_subdomains_present():
    result = sql_case_when()
    for subdomain in SUBDOMAINS:
        assert subdomain in result, \
            f"sql_case_when() missing subdomain '{subdomain}'"


def test_sql_case_when_default_column_is_fqdn():
    result = sql_case_when()
    assert "fqdn LIKE" in result, \
        "Default column name should be 'fqdn'"


def test_sql_case_when_custom_column_name():
    result = sql_case_when(col="my_col")
    assert "my_col LIKE" in result, \
        "Custom column name should appear in WHEN clauses"
    assert "fqdn LIKE" not in result, \
        "Default column name should not appear when custom column is specified"


def test_sql_case_when_when_then_structure():
    result = sql_case_when()
    lines = result.splitlines()
    when_lines = [ln for ln in lines if ln.strip().startswith("WHEN")]
    assert len(when_lines) == len(SUBDOMAIN_DEFS), \
        f"Expected {len(SUBDOMAIN_DEFS)} WHEN clauses, found {len(when_lines)}"


def test_sql_case_when_like_pattern():
    """Each WHEN clause should use a LIKE pattern ending in .%"""
    result = sql_case_when()
    for subdomain in SUBDOMAINS:
        expected_pattern = f"LIKE '{subdomain}.%'"
        assert expected_pattern in result, \
            f"Expected LIKE pattern '{expected_pattern}' in sql_case_when() output"


def test_sql_case_when_specificity_ordering_in_output():
    """ss.epdg.epc must appear before epdg.epc in the generated SQL."""
    result = sql_case_when()
    idx_specific = result.find("ss.epdg.epc")
    idx_generic = result.find("'epdg.epc'")
    assert idx_specific < idx_generic, \
        "ss.epdg.epc WHEN clause must precede epdg.epc WHEN clause in SQL output"
