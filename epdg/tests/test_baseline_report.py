"""
Unit tests for pure-logic constants and severity rules in
epdg/3gpppub-baseline-report.py.

DB-dependent functions are not tested here; only constants and logic
that can be exercised without a SQLite connection.
"""

import importlib.util
import os
import sys

import pytest

# ── Load the script module without executing main() ──────────────────────────

_SCRIPT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "3gpppub-baseline-report.py"
)
_SCRIPT_PATH = os.path.abspath(_SCRIPT_PATH)

_mod = None
_load_error = None

try:
    spec = importlib.util.spec_from_file_location("baseline_report", _SCRIPT_PATH)
    _mod = importlib.util.module_from_spec(spec)
    # Prevent argparse / sys.exit from firing on import
    _orig_argv = sys.argv
    sys.argv = ["3gpppub-baseline-report.py"]
    try:
        spec.loader.exec_module(_mod)
    finally:
        sys.argv = _orig_argv
except Exception as exc:
    _load_error = exc

# Skip the entire module if the script cannot be imported
if _load_error is not None:
    pytestmark = pytest.mark.skip(
        reason=f"Could not import baseline report script: {_load_error}"
    )


# ── Helper: require the module to be loaded ───────────────────────────────────

def _require_mod():
    if _mod is None:
        pytest.skip(f"baseline report module not available: {_load_error}")
    return _mod


# ── SEVERITY_ORDER ────────────────────────────────────────────────────────────

def test_severity_order_exists():
    mod = _require_mod()
    assert hasattr(mod, "SEVERITY_ORDER"), "SEVERITY_ORDER constant not found"


def test_severity_order_has_exactly_five_elements():
    mod = _require_mod()
    assert len(mod.SEVERITY_ORDER) == 5, \
        f"SEVERITY_ORDER should have 5 elements, got {len(mod.SEVERITY_ORDER)}"


@pytest.mark.parametrize("level", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
def test_severity_order_contains_level(level):
    mod = _require_mod()
    assert level in mod.SEVERITY_ORDER, \
        f"SEVERITY_ORDER is missing '{level}'"


def test_severity_order_ordering():
    """CRITICAL must be first, INFO must be last."""
    mod = _require_mod()
    assert mod.SEVERITY_ORDER[0] == "CRITICAL"
    assert mod.SEVERITY_ORDER[-1] == "INFO"


def test_severity_order_descending_criticality():
    mod = _require_mod()
    expected = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert mod.SEVERITY_ORDER == expected


# ── CONTROL_MAP ───────────────────────────────────────────────────────────────

def test_control_map_exists():
    mod = _require_mod()
    assert hasattr(mod, "CONTROL_MAP"), "CONTROL_MAP constant not found"


def test_control_map_has_at_least_eight_entries():
    mod = _require_mod()
    assert len(mod.CONTROL_MAP) >= 8, \
        f"CONTROL_MAP should have >= 8 entries, got {len(mod.CONTROL_MAP)}"


@pytest.mark.parametrize("finding_type,entry", [
    pytest.param(ft, entry, id=ft)
    for ft, entry in {
        "expired_cert":     ("GSMA FS.31 4.3",       "CRITICAL", "Expired TLS Certificate"),
        "self_signed_cert": ("GSMA FS.31 4.3",        "HIGH",     "Self-Signed TLS Certificate"),
        "weak_sig_cert":    ("GSMA NESAS/TS 33.310",  "HIGH",     "SHA-1/MD5 Certificate Signature"),
        "weak_ike_crypto":  ("3GPP TS 33.402 7.3",   "HIGH",     "Weak IKEv2 Cipher Suite"),
        "5gc_pub_leak":     ("3GPP TS 29.573 4.4",   "HIGH",     "5GC NF Exposed in Public DNS Zone"),
        "sepp_pub_leak":    ("3GPP TS 29.573 4.4",   "CRITICAL", "SEPP Exposed in Public DNS Zone"),
        "missing_epdg":     ("3GPP TS 24.302",        "MEDIUM",   "No VoWiFi ePDG Published"),
        "missing_ims":      ("3GPP TS 24.229",        "MEDIUM",   "No IMS Entry Point Published"),
        "missing_sos":      ("3GPP TS 23.167",        "MEDIUM",   "No Emergency SOS Published"),
        "missing_bsf":      ("3GPP TS 33.220",        "LOW",      "No BSF Auth Published"),
        "diameter_public":  ("GSMA IR.88 4.2",        "HIGH",     "Diameter Realm on Public DNS"),
    }.items()
])
def test_control_map_known_entry_present(finding_type, entry):
    mod = _require_mod()
    assert finding_type in mod.CONTROL_MAP, \
        f"CONTROL_MAP missing expected key '{finding_type}'"


def test_control_map_each_entry_has_three_fields():
    mod = _require_mod()
    for finding_type, value in mod.CONTROL_MAP.items():
        assert len(value) == 3, \
            f"CONTROL_MAP['{finding_type}'] should be a 3-tuple " \
            f"(control_ref, severity, title), got length {len(value)}"


def test_control_map_entry_types():
    mod = _require_mod()
    for finding_type, (control_ref, severity, title) in mod.CONTROL_MAP.items():
        assert isinstance(control_ref, str) and control_ref, \
            f"CONTROL_MAP['{finding_type}'] control_ref must be a non-empty string"
        assert isinstance(severity, str) and severity, \
            f"CONTROL_MAP['{finding_type}'] severity must be a non-empty string"
        assert isinstance(title, str) and title, \
            f"CONTROL_MAP['{finding_type}'] title must be a non-empty string"


def test_control_map_all_severities_are_valid():
    mod = _require_mod()
    valid = set(mod.SEVERITY_ORDER)
    for finding_type, (control_ref, severity, title) in mod.CONTROL_MAP.items():
        assert severity in valid, \
            f"CONTROL_MAP['{finding_type}'] has invalid severity '{severity}'. " \
            f"Must be one of {sorted(valid)}"


def test_control_map_expired_cert_is_critical():
    mod = _require_mod()
    _, severity, _ = mod.CONTROL_MAP["expired_cert"]
    assert severity == "CRITICAL"


def test_control_map_sepp_pub_leak_is_critical():
    mod = _require_mod()
    _, severity, _ = mod.CONTROL_MAP["sepp_pub_leak"]
    assert severity == "CRITICAL"


def test_control_map_missing_entries_are_medium_or_lower():
    """missing_* findings should be MEDIUM or lower."""
    mod = _require_mod()
    medium_or_lower = {"MEDIUM", "LOW", "INFO"}
    missing_keys = [k for k in mod.CONTROL_MAP if k.startswith("missing_")]
    assert missing_keys, "Expected at least one missing_* key in CONTROL_MAP"
    for key in missing_keys:
        _, severity, _ = mod.CONTROL_MAP[key]
        assert severity in medium_or_lower, \
            f"CONTROL_MAP['{key}'] severity '{severity}' should be MEDIUM or lower"


# ── SCHEMA_BASELINE ───────────────────────────────────────────────────────────

def test_schema_baseline_exists():
    mod = _require_mod()
    assert hasattr(mod, "SCHEMA_BASELINE"), "SCHEMA_BASELINE constant not found"


def test_schema_baseline_contains_create_table():
    mod = _require_mod()
    assert "CREATE TABLE IF NOT EXISTS risk_findings" in mod.SCHEMA_BASELINE, \
        "SCHEMA_BASELINE must contain 'CREATE TABLE IF NOT EXISTS risk_findings'"


def test_schema_baseline_contains_severity_column():
    mod = _require_mod()
    assert "severity" in mod.SCHEMA_BASELINE


def test_schema_baseline_contains_control_ref_column():
    mod = _require_mod()
    assert "control_ref" in mod.SCHEMA_BASELINE


def test_schema_baseline_contains_finding_type_column():
    mod = _require_mod()
    assert "finding_type" in mod.SCHEMA_BASELINE


def test_schema_baseline_contains_operator_column():
    mod = _require_mod()
    assert "operator" in mod.SCHEMA_BASELINE


# ── build_summary logic ───────────────────────────────────────────────────────

def test_build_summary_empty_findings():
    mod = _require_mod()
    summary = mod.build_summary([])
    assert summary["total"] == 0
    for sev in mod.SEVERITY_ORDER:
        assert summary["counts"][sev] == 0
    assert summary["top_operators"] == []


def test_build_summary_counts_severities():
    mod = _require_mod()
    findings = [
        {"severity": "CRITICAL", "operator": "OpA"},
        {"severity": "CRITICAL", "operator": "OpA"},
        {"severity": "HIGH",     "operator": "OpB"},
        {"severity": "INFO",     "operator": "OpC"},
    ]
    summary = mod.build_summary(findings)
    assert summary["total"] == 4
    assert summary["counts"]["CRITICAL"] == 2
    assert summary["counts"]["HIGH"] == 1
    assert summary["counts"]["INFO"] == 1
    assert summary["counts"]["MEDIUM"] == 0
    assert summary["counts"]["LOW"] == 0


def test_build_summary_top_operators_sorted_by_risk():
    mod = _require_mod()
    findings = [
        {"severity": "INFO",     "operator": "OpLow"},
        {"severity": "CRITICAL", "operator": "OpHigh"},
        {"severity": "CRITICAL", "operator": "OpHigh"},
        {"severity": "HIGH",     "operator": "OpMid"},
    ]
    summary = mod.build_summary(findings)
    ops = [op for op, _ in summary["top_operators"]]
    assert ops[0] == "OpHigh", "Highest-risk operator should be first"


def test_build_summary_top_operators_max_five():
    mod = _require_mod()
    findings = [
        {"severity": "HIGH", "operator": f"Op{i}"}
        for i in range(10)
    ]
    summary = mod.build_summary(findings)
    assert len(summary["top_operators"]) <= 5
