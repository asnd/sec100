"""
Single source of truth for pub.3gppnetwork.org subdomain definitions.

To add a new subdomain, append one dict to SUBDOMAIN_DEFS.
All other constants (SUBDOMAINS, SERVICE_COLORS, SCORE_WEIGHTS) and the
SQL CASE WHEN generator derive from this list automatically.

Field reference
---------------
subdomain  : str   — label used in FQDN construction
category   : str   — logical group (vowifi / 5g / ims / emergency / auth / access / messaging / provisioning)
label      : str   — human-readable name shown in the dashboard
score      : int   — capability-score points (0 = informational only)
color      : str   — hex color for Plotly charts
icon       : str   — emoji for score breakdown display (optional)
naptr_probe: bool  — whether NAPTR/SRV probing makes sense for this service

ORDERING RULE: more-specific prefixes MUST appear before less-specific ones
(e.g. "ss.epdg.epc" before "epdg.epc", "sos.ims" before "ims").
This order is used directly by fqdn_to_service() and sql_case_when().
"""

SUBDOMAIN_DEFS: list[dict] = [
    # ── VoWiFi / ePDG ──────────────────────────────────────────────────────────
    dict(subdomain="ss.epdg.epc",  category="vowifi",       label="ePDG Steering",        score=0,  color="#aec7e8", icon="",   naptr_probe=False),
    dict(subdomain="sos.epdg.epc", category="emergency",    label="Emergency ePDG",       score=0,  color="#17becf", icon="🆘", naptr_probe=False),
    dict(subdomain="epdg.epc",     category="vowifi",       label="VoWiFi (ePDG)",        score=20, color="#1f77b4", icon="📶", naptr_probe=True),
    dict(subdomain="vowifi",       category="vowifi",       label="VoWiFi alias",          score=0,  color="#9edae5", icon="",   naptr_probe=False),
    # ── 5G non-3GPP ────────────────────────────────────────────────────────────
    dict(subdomain="n3iwf.5gc",    category="5g",           label="5G N3IWF",             score=15, color="#bcbd22", icon="🛜", naptr_probe=True),
    # ── IMS / VoLTE (specific before generic) ──────────────────────────────────
    dict(subdomain="pcscf.ims",    category="ims",          label="P-CSCF",               score=10, color="#ffbb78", icon="🔀", naptr_probe=True),
    dict(subdomain="mmtel.ims",    category="ims",          label="MMTel",                score=0,  color="#ff9896", icon="",   naptr_probe=False),
    dict(subdomain="xcap.ims",     category="ims",          label="XCAP",                 score=10, color="#d62728", icon="⚙️", naptr_probe=False),
    dict(subdomain="ut.ims",       category="ims",          label="Ut interface",          score=0,  color="#e377c2", icon="",   naptr_probe=False),
    dict(subdomain="sos.ims",      category="emergency",    label="Emergency IMS",        score=0,  color="#f7b6d2", icon="🆘", naptr_probe=True),
    dict(subdomain="ims",          category="ims",          label="VoLTE (IMS)",          score=15, color="#ff7f0e", icon="📞", naptr_probe=True),
    # ── Emergency ──────────────────────────────────────────────────────────────
    dict(subdomain="sos",          category="emergency",    label="Emergency SOS",        score=5,  color="#e41a1c", icon="🆘", naptr_probe=False),
    dict(subdomain="aes",          category="emergency",    label="Auth/Emergency (MX)",  score=0,  color="#c49c94", icon="",   naptr_probe=False),
    # ── Other ──────────────────────────────────────────────────────────────────
    dict(subdomain="bsf",          category="auth",         label="BSF (5G Auth)",        score=10, color="#2ca02c", icon="🔐", naptr_probe=False),
    dict(subdomain="gan",          category="access",       label="GAN/UMA",              score=5,  color="#9467bd", icon="📡", naptr_probe=False),
    dict(subdomain="rcs",          category="messaging",    label="RCS",                  score=10, color="#8c564b", icon="💬", naptr_probe=True),
    dict(subdomain="subs",         category="provisioning", label="Subscriptions",        score=0,  color="#7f7f7f", icon="",   naptr_probe=False),
    dict(subdomain="cota-sdk",     category="provisioning", label="COTA OTA",             score=0,  color="#c5b0d5", icon="",   naptr_probe=False),
]

# ── Derived constants (do not edit — computed from SUBDOMAIN_DEFS) ──────────────

SUBDOMAINS: list[str] = [d["subdomain"] for d in SUBDOMAIN_DEFS]

SERVICE_COLORS: dict[str, str] = {d["subdomain"]: d["color"] for d in SUBDOMAIN_DEFS}
SERVICE_COLORS["other"] = "#c7c7c7"

# Only services with score > 0 appear in capability scoring
SCORE_WEIGHTS: dict[str, tuple[str, int, str]] = {
    d["subdomain"]: (d["label"], d["score"], d["icon"])
    for d in SUBDOMAIN_DEFS
    if d["score"] > 0
}

# Services where NAPTR/SRV probing is useful
NAPTR_PROBE_SERVICES: list[str] = [d["subdomain"] for d in SUBDOMAIN_DEFS if d["naptr_probe"]]


# ── Helper functions ────────────────────────────────────────────────────────────

def fqdn_to_service(fqdn: str) -> str:
    """Return the service label for a given FQDN.

    Iterates SUBDOMAIN_DEFS in definition order, so more-specific prefixes
    match before generic ones (e.g. 'ss.epdg.epc' before 'epdg.epc').
    """
    for d in SUBDOMAIN_DEFS:
        if fqdn.startswith(d["subdomain"] + "."):
            return d["subdomain"]
    return "other"


def sql_case_when(col: str = "fqdn") -> str:
    """Return a SQL CASE WHEN … END expression mapping *col* to service label.

    The generated expression respects specificity ordering from SUBDOMAIN_DEFS.

    Example usage in a query::

        SELECT fqdn, ({sql_case_when()}) AS service FROM available_fqdns
    """
    lines = ["CASE"]
    for d in SUBDOMAIN_DEFS:
        s = d["subdomain"]
        lines.append(f"  WHEN {col} LIKE '{s}.%' THEN '{s}'")
    lines.append("  ELSE 'other'")
    lines.append("END")
    return "\n".join(lines)
