#!/usr/bin/env python3
"""
GSMA FS.31 / ETSI Security Baseline Scoring & Compliance Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Synthesises all collected DB signals into per-operator risk verdicts mapped
to GSMA FS.31, 3GPP TS, and ETSI controls.

This is a read-only analysis script; it only writes to the risk_findings table.

Usage:
  python3 3gpppub-baseline-report.py --db database.db
  python3 3gpppub-baseline-report.py --db database.db --collect
  python3 3gpppub-baseline-report.py --db database.db --format json --output report.json
  python3 3gpppub-baseline-report.py --db database.db --operator Vodafone --severity-min HIGH
  python3 3gpppub-baseline-report.py --db database.db --summary-only
"""

import argparse
import json
import logging
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA_BASELINE = """
CREATE TABLE IF NOT EXISTS risk_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    operator     TEXT NOT NULL,
    country_name TEXT,
    mcc          INTEGER,
    mnc          INTEGER,
    control_ref  TEXT,
    finding_type TEXT,
    severity     TEXT,
    title        TEXT,
    evidence     TEXT,
    detected_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(operator, finding_type, control_ref)
);
"""

# ── Control map ───────────────────────────────────────────────────────────────
# finding_type -> (control_ref, severity, title)

CONTROL_MAP = {
    "expired_cert":      ("GSMA FS.31 4.3",          "CRITICAL", "Expired TLS Certificate"),
    "self_signed_cert":  ("GSMA FS.31 4.3",          "HIGH",     "Self-Signed TLS Certificate"),
    "weak_sig_cert":     ("GSMA NESAS/TS 33.310",    "HIGH",     "SHA-1/MD5 Certificate Signature"),
    "weak_ike_crypto":   ("3GPP TS 33.402 7.3",      "HIGH",     "Weak IKEv2 Cipher Suite"),
    "5gc_pub_leak":      ("3GPP TS 29.573 4.4",      "HIGH",     "5GC NF Exposed in Public DNS Zone"),
    "sepp_pub_leak":     ("3GPP TS 29.573 4.4",      "CRITICAL", "SEPP Exposed in Public DNS Zone"),
    "missing_epdg":      ("3GPP TS 24.302",          "MEDIUM",   "No VoWiFi ePDG Published"),
    "missing_ims":       ("3GPP TS 24.229",          "MEDIUM",   "No IMS Entry Point Published"),
    "missing_sos":       ("3GPP TS 23.167",          "MEDIUM",   "No Emergency SOS Published"),
    "missing_bsf":       ("3GPP TS 33.220",          "LOW",      "No BSF Auth Published"),
    "diameter_public":   ("GSMA IR.88 4.2",          "HIGH",     "Diameter Realm on Public DNS"),
    "rsp_smdp_exposed":  ("GSMA SGP.22 4.1",         "INFO",     "SM-DP+ Endpoint Discovered"),
    "rsp_smds_exposed":  ("GSMA SGP.22 4.1",         "INFO",     "SM-DS Endpoint Discovered"),
    "ct_new_prefix":     ("Informational",           "INFO",     "New 3GPP Prefix via CT Logs"),
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ── DB helpers ────────────────────────────────────────────────────────────────

def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_BASELINE)
    conn.commit()


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


# ── Collection functions ──────────────────────────────────────────────────────

def _operator_meta(conn: sqlite3.Connection) -> dict[str, dict]:
    """Return {operator: {mcc, mnc, country_name}} from available_fqdns."""
    rows = conn.execute(
        """
        SELECT DISTINCT operator,
               mcc,
               mnc,
               country_name
        FROM available_fqdns
        """
    ).fetchall()
    meta: dict[str, dict] = {}
    for op, mcc, mnc, country in rows:
        if op and op not in meta:
            meta[op] = {"mcc": mcc, "mnc": mnc, "country_name": country}
    return meta


def collect_tls_findings(conn: sqlite3.Connection) -> list[dict]:
    """Query tls_certs for expired, self-signed, or weak-signature certificates."""
    if not table_exists(conn, "tls_certs"):
        log.debug("Table tls_certs not found — skipping TLS findings")
        return []

    findings = []
    rows = conn.execute(
        """
        SELECT operator, mcc, mnc, country_name, fqdn,
               is_expired, is_self_signed, is_weak_sig,
               subject, not_after, sig_algorithm
        FROM tls_certs
        WHERE is_expired = 1 OR is_self_signed = 1 OR is_weak_sig = 1
        """
    ).fetchall()

    for row in rows:
        (operator, mcc, mnc, country_name, fqdn,
         is_expired, is_self_signed, is_weak_sig,
         subject, not_after, sig_algorithm) = row

        if is_expired:
            findings.append({
                "operator":     operator,
                "country_name": country_name,
                "mcc":          mcc,
                "mnc":          mnc,
                "finding_type": "expired_cert",
                "evidence":     f"fqdn={fqdn} subject={subject} not_after={not_after}",
            })
        if is_self_signed:
            findings.append({
                "operator":     operator,
                "country_name": country_name,
                "mcc":          mcc,
                "mnc":          mnc,
                "finding_type": "self_signed_cert",
                "evidence":     f"fqdn={fqdn} subject={subject}",
            })
        if is_weak_sig:
            findings.append({
                "operator":     operator,
                "country_name": country_name,
                "mcc":          mcc,
                "mnc":          mnc,
                "finding_type": "weak_sig_cert",
                "evidence":     f"fqdn={fqdn} sig_algorithm={sig_algorithm}",
            })

    log.info("TLS findings collected: %d", len(findings))
    return findings


def collect_ike_findings(conn: sqlite3.Connection) -> list[dict]:
    """Query ike_probes for weak IKEv2 cipher suites."""
    if not table_exists(conn, "ike_probes"):
        log.debug("Table ike_probes not found — skipping IKE findings")
        return []

    rows = conn.execute(
        """
        SELECT operator, mcc, mnc, country_name, fqdn,
               cipher_suite, transform_ids
        FROM ike_probes
        WHERE weak_crypto = 1
        """
    ).fetchall()

    findings = []
    for operator, mcc, mnc, country_name, fqdn, cipher_suite, transform_ids in rows:
        findings.append({
            "operator":     operator,
            "country_name": country_name,
            "mcc":          mcc,
            "mnc":          mnc,
            "finding_type": "weak_ike_crypto",
            "evidence":     f"fqdn={fqdn} cipher_suite={cipher_suite} transforms={transform_ids}",
        })

    log.info("IKE findings collected: %d", len(findings))
    return findings


def collect_5gc_findings(conn: sqlite3.Connection) -> list[dict]:
    """Query fiveg_fqdns for 5GC NFs exposed in public DNS zones."""
    if not table_exists(conn, "fiveg_fqdns"):
        log.debug("Table fiveg_fqdns not found — skipping 5GC findings")
        return []

    rows = conn.execute(
        """
        SELECT operator, mcc, mnc, country_name, fqdn, nf_type, resolved_ip
        FROM fiveg_fqdns
        WHERE dns_zone = 'pub'
        """
    ).fetchall()

    findings = []
    for operator, mcc, mnc, country_name, fqdn, nf_type, resolved_ip in rows:
        ftype = "sepp_pub_leak" if (nf_type or "").lower() == "sepp" else "5gc_pub_leak"
        findings.append({
            "operator":     operator,
            "country_name": country_name,
            "mcc":          mcc,
            "mnc":          mnc,
            "finding_type": ftype,
            "evidence":     f"fqdn={fqdn} nf_type={nf_type} ip={resolved_ip}",
        })

    log.info("5GC findings collected: %d", len(findings))
    return findings


def collect_missing_service_findings(conn: sqlite3.Connection) -> list[dict]:
    """
    For each operator with at least one published FQDN (active), check which
    key services are absent in available_fqdns and raise a missing_* finding.
    """
    if not table_exists(conn, "available_fqdns"):
        log.debug("Table available_fqdns not found — skipping missing-service findings")
        return []

    # Collect per-operator presence flags
    rows = conn.execute(
        """
        SELECT operator, mcc, mnc, country_name, fqdn
        FROM available_fqdns
        WHERE fqdn IS NOT NULL AND fqdn != ''
        """
    ).fetchall()

    presence: dict[str, dict] = {}
    meta: dict[str, dict] = {}

    for operator, mcc, mnc, country_name, fqdn in rows:
        if not operator:
            continue
        if operator not in presence:
            presence[operator] = {
                "has_epdg": False,
                "has_ims":  False,
                "has_sos":  False,
                "has_bsf":  False,
            }
            meta[operator] = {"mcc": mcc, "mnc": mnc, "country_name": country_name}

        fl = fqdn.lower()
        if "epdg.epc." in fl:
            presence[operator]["has_epdg"] = True
        if fl.startswith("ims.") or ".ims." in fl or "ims.mnc" in fl:
            presence[operator]["has_ims"] = True
        if "sos." in fl:
            presence[operator]["has_sos"] = True
        if "bsf." in fl:
            presence[operator]["has_bsf"] = True

    findings = []
    for operator, flags in presence.items():
        m = meta[operator]
        base = {
            "operator":     operator,
            "country_name": m["country_name"],
            "mcc":          m["mcc"],
            "mnc":          m["mnc"],
        }
        if not flags["has_epdg"]:
            findings.append({**base, "finding_type": "missing_epdg",
                              "evidence": f"operator={operator} has no epdg.epc.* FQDN"})
        if not flags["has_ims"]:
            findings.append({**base, "finding_type": "missing_ims",
                              "evidence": f"operator={operator} has no ims.* FQDN"})
        if not flags["has_sos"]:
            findings.append({**base, "finding_type": "missing_sos",
                              "evidence": f"operator={operator} has no sos.* FQDN"})
        if not flags["has_bsf"]:
            findings.append({**base, "finding_type": "missing_bsf",
                              "evidence": f"operator={operator} has no bsf.* FQDN"})

    log.info("Missing-service findings collected: %d", len(findings))
    return findings


def collect_diameter_findings(conn: sqlite3.Connection) -> list[dict]:
    """Query diameter_realms where NAPTR was found (realm on public DNS)."""
    if not table_exists(conn, "diameter_realms"):
        log.debug("Table diameter_realms not found — skipping Diameter findings")
        return []

    rows = conn.execute(
        """
        SELECT operator, mcc, mnc, country_name, realm, naptr_records
        FROM diameter_realms
        WHERE naptr_found = 1
        """
    ).fetchall()

    findings = []
    for operator, mcc, mnc, country_name, realm, naptr_records in rows:
        findings.append({
            "operator":     operator,
            "country_name": country_name,
            "mcc":          mcc,
            "mnc":          mnc,
            "finding_type": "diameter_public",
            "evidence":     f"realm={realm} naptr_records={naptr_records}",
        })

    log.info("Diameter findings collected: %d", len(findings))
    return findings


def collect_rsp_findings(conn: sqlite3.Connection) -> list[dict]:
    """Query rsp_endpoints and map by role to SM-DP+ / SM-DS finding types."""
    if not table_exists(conn, "rsp_endpoints"):
        log.debug("Table rsp_endpoints not found — skipping RSP findings")
        return []

    rows = conn.execute(
        """
        SELECT operator, mcc, mnc, country_name, endpoint, role, resolved_ip
        FROM rsp_endpoints
        """
    ).fetchall()

    findings = []
    for operator, mcc, mnc, country_name, endpoint, role, resolved_ip in rows:
        role_upper = (role or "").upper()
        if "SM-DP" in role_upper or "SMDP" in role_upper:
            ftype = "rsp_smdp_exposed"
        else:
            ftype = "rsp_smds_exposed"
        findings.append({
            "operator":     operator,
            "country_name": country_name,
            "mcc":          mcc,
            "mnc":          mnc,
            "finding_type": ftype,
            "evidence":     f"endpoint={endpoint} role={role} ip={resolved_ip}",
        })

    log.info("RSP findings collected: %d", len(findings))
    return findings


def collect_ct_findings(conn: sqlite3.Connection) -> list[dict]:
    """Query discovered_hosts for new CT-log candidates (one finding per unique service_prefix)."""
    if not table_exists(conn, "discovered_hosts"):
        log.debug("Table discovered_hosts not found — skipping CT findings")
        return []

    rows = conn.execute(
        """
        SELECT operator, mcc, mnc, country_name, hostname, service_prefix, first_seen
        FROM discovered_hosts
        WHERE is_new_candidate = 1
        """
    ).fetchall()

    # Deduplicate: one finding per (operator, service_prefix) pair
    seen: set[tuple] = set()
    findings = []
    for operator, mcc, mnc, country_name, hostname, service_prefix, first_seen in rows:
        key = (operator, service_prefix)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "operator":     operator,
            "country_name": country_name,
            "mcc":          mcc,
            "mnc":          mnc,
            "finding_type": "ct_new_prefix",
            "evidence":     (
                f"service_prefix={service_prefix} "
                f"example_hostname={hostname} "
                f"first_seen={first_seen}"
            ),
        })

    log.info("CT findings collected: %d", len(findings))
    return findings


# ── Save findings ─────────────────────────────────────────────────────────────

def save_findings(conn: sqlite3.Connection, findings: list[dict]) -> int:
    """INSERT OR REPLACE each finding into risk_findings. Returns rows upserted."""
    if not findings:
        return 0

    upserted = 0
    for f in findings:
        ftype = f.get("finding_type", "")
        ctrl_ref, severity, title = CONTROL_MAP.get(ftype, ("Unknown", "INFO", ftype))
        conn.execute(
            """
            INSERT INTO risk_findings
                (operator, country_name, mcc, mnc,
                 control_ref, finding_type, severity, title, evidence)
            VALUES
                (:operator, :country_name, :mcc, :mnc,
                 :control_ref, :finding_type, :severity, :title, :evidence)
            ON CONFLICT(operator, finding_type, control_ref) DO UPDATE SET
                country_name = excluded.country_name,
                mcc          = excluded.mcc,
                mnc          = excluded.mnc,
                severity     = excluded.severity,
                title        = excluded.title,
                evidence     = excluded.evidence,
                detected_at  = CURRENT_TIMESTAMP
            """,
            {
                "operator":     f.get("operator", ""),
                "country_name": f.get("country_name"),
                "mcc":          f.get("mcc"),
                "mnc":          f.get("mnc"),
                "control_ref":  ctrl_ref,
                "finding_type": ftype,
                "severity":     severity,
                "title":        title,
                "evidence":     f.get("evidence", ""),
            },
        )
        upserted += 1

    conn.commit()
    return upserted


# ── Load findings from DB ─────────────────────────────────────────────────────

def load_findings(conn: sqlite3.Connection,
                  operator_filter: Optional[str] = None,
                  severity_min: str = "INFO") -> list[dict]:
    """Load risk_findings rows, optionally filtered by operator substring and min severity."""
    min_idx = SEVERITY_ORDER.index(severity_min) if severity_min in SEVERITY_ORDER else len(SEVERITY_ORDER) - 1
    allowed = set(SEVERITY_ORDER[: min_idx + 1])

    placeholders = ",".join("?" * len(allowed))
    params: list = list(allowed)

    sql = f"""
        SELECT id, operator, country_name, mcc, mnc,
               control_ref, finding_type, severity, title, evidence, detected_at
        FROM risk_findings
        WHERE severity IN ({placeholders})
    """
    if operator_filter:
        sql += " AND operator LIKE ?"
        params.append(f"%{operator_filter}%")

    sql += " ORDER BY CASE severity " + " ".join(
        f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITY_ORDER)
    ) + " END, operator"

    rows = conn.execute(sql, params).fetchall()
    cols = ["id", "operator", "country_name", "mcc", "mnc",
            "control_ref", "finding_type", "severity", "title", "evidence", "detected_at"]
    return [dict(zip(cols, r)) for r in rows]


# ── Summary helpers ───────────────────────────────────────────────────────────

def build_summary(findings: list[dict]) -> dict:
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    op_score: dict[str, int] = defaultdict(int)
    for f in findings:
        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1
        # Weight CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0 for ranking
        weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev, 0)
        op_score[f["operator"]] += weight

    top5 = sorted(op_score.items(), key=lambda x: -x[1])[:5]
    return {"counts": counts, "top_operators": top5, "total": len(findings)}


def print_summary_section(findings: list[dict]) -> None:
    summary = build_summary(findings)
    print("\n=== Executive Summary ===")
    print(f"Total findings: {summary['total']}")
    for sev in SEVERITY_ORDER:
        n = summary["counts"].get(sev, 0)
        bar = "█" * min(n, 40)
        print(f"  {sev:<10} {n:>5}  {bar}")

    print("\nTop 5 operators by risk (CRITICAL+HIGH weight):")
    for op, score in summary["top_operators"]:
        print(f"  {op:<40} score={score}")


# ── Report generators ─────────────────────────────────────────────────────────

def _try_rich() -> tuple:
    """Return (Console, Table) if rich is available, else (None, None)."""
    try:
        from rich.console import Console  # type: ignore
        from rich.table import Table      # type: ignore
        return Console(), Table
    except ImportError:
        return None, None


def generate_text(findings: list[dict], top_n: int, summary_only: bool) -> str:
    """Plain-text or rich-table report."""
    lines: list[str] = []
    summary = build_summary(findings)

    # Executive Summary
    lines.append("=" * 70)
    lines.append("3GPP Security Baseline Report  (GSMA FS.31 / ETSI / 3GPP TS)")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("=" * 70)
    lines.append(f"\nTotal findings: {summary['total']}")
    for sev in SEVERITY_ORDER:
        n = summary["counts"].get(sev, 0)
        bar = "=" * min(n, 30)
        lines.append(f"  {sev:<10} {n:>5}  {bar}")

    lines.append("\nTop operators by risk weight:")
    for op, score in summary["top_operators"]:
        lines.append(f"  {op:<40} score={score}")

    if summary_only:
        return "\n".join(lines)

    # Findings by Severity
    lines.append("\n" + "-" * 70)
    lines.append("Findings by Severity")
    lines.append("-" * 70)

    by_sev: dict[str, list[dict]] = defaultdict(list)
    for f in findings[:top_n]:
        by_sev[f["severity"]].append(f)

    console, RichTable = _try_rich()

    for sev in SEVERITY_ORDER:
        group = by_sev.get(sev, [])
        if not group:
            continue
        lines.append(f"\n[{sev}] ({len(group)} findings)")

        if console and RichTable:
            # Use rich for pretty output; we'll print inline via rich,
            # then add a placeholder marker in the plain buffer so callers
            # that capture output still see something meaningful.
            import io
            from rich.console import Console as _C
            from rich.table import Table as _T
            buf = io.StringIO()
            c = _C(file=buf, highlight=False, width=120)
            t = _T(show_header=True, header_style="bold")
            t.add_column("Operator", style="cyan", no_wrap=True, max_width=30)
            t.add_column("MCC-MNC", max_width=10)
            t.add_column("Control Ref", max_width=22)
            t.add_column("Title", max_width=35)
            t.add_column("Evidence", max_width=50)
            for f in group:
                mcc_mnc = f"{f['mcc']}-{f['mnc']}" if f["mcc"] and f["mnc"] else ""
                t.add_row(
                    f["operator"] or "",
                    mcc_mnc,
                    f["control_ref"] or "",
                    f["title"] or "",
                    (f["evidence"] or "")[:120],
                )
            c.print(t)
            lines.append(buf.getvalue())
        else:
            # Plain fallback
            hdr = f"  {'Operator':<30} {'MCC-MNC':<10} {'Control Ref':<22} {'Title':<35}"
            lines.append(hdr)
            lines.append("  " + "-" * (len(hdr) - 2))
            for f in group:
                mcc_mnc = f"{f['mcc']}-{f['mnc']}" if f["mcc"] and f["mnc"] else ""
                lines.append(
                    f"  {(f['operator'] or ''):<30} "
                    f"{mcc_mnc:<10} "
                    f"{(f['control_ref'] or ''):<22} "
                    f"{(f['title'] or ''):<35}"
                )
                if f.get("evidence"):
                    lines.append(f"    Evidence: {f['evidence'][:120]}")

    return "\n".join(lines)


def generate_json(findings: list[dict], top_n: int, summary_only: bool) -> str:
    summary = build_summary(findings)
    payload: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total":        summary["total"],
            "counts":       summary["counts"],
            "top_operators": [{"operator": op, "risk_score": score}
                               for op, score in summary["top_operators"]],
        },
    }
    if not summary_only:
        payload["findings"] = findings[:top_n]
    return json.dumps(payload, indent=2, default=str)


def generate_markdown(findings: list[dict], top_n: int, summary_only: bool) -> str:
    summary = build_summary(findings)
    lines: list[str] = []

    lines.append("# 3GPP Security Baseline Report")
    lines.append(f"\n_Generated: {datetime.now(timezone.utc).isoformat()}_\n")

    lines.append("## Executive Summary\n")
    lines.append(f"**Total findings:** {summary['total']}\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {summary['counts'].get(sev, 0)} |")

    lines.append("\n**Top 5 operators by risk weight:**\n")
    lines.append("| Operator | Risk Score |")
    lines.append("|----------|----------:|")
    for op, score in summary["top_operators"]:
        lines.append(f"| {op} | {score} |")

    if summary_only:
        return "\n".join(lines)

    lines.append("\n## Findings by Severity\n")
    by_sev: dict[str, list[dict]] = defaultdict(list)
    for f in findings[:top_n]:
        by_sev[f["severity"]].append(f)

    for sev in SEVERITY_ORDER:
        group = by_sev.get(sev, [])
        if not group:
            continue
        lines.append(f"\n### {sev} ({len(group)})\n")
        lines.append("| Operator | MCC-MNC | Control Ref | Title | Evidence |")
        lines.append("|----------|---------|-------------|-------|----------|")
        for f in group:
            mcc_mnc = f"{f['mcc']}-{f['mnc']}" if f["mcc"] and f["mnc"] else ""
            ev = (f["evidence"] or "").replace("|", "\\|")[:100]
            lines.append(
                f"| {f['operator'] or ''} "
                f"| {mcc_mnc} "
                f"| {f['control_ref'] or ''} "
                f"| {f['title'] or ''} "
                f"| {ev} |"
            )

    return "\n".join(lines)


def generate_html(findings: list[dict], top_n: int, summary_only: bool) -> str:
    summary = build_summary(findings)
    ts = datetime.now(timezone.utc).isoformat()

    sev_colors = {
        "CRITICAL": "#c0392b",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "LOW":      "#2980b9",
        "INFO":     "#27ae60",
    }

    def badge(sev: str) -> str:
        color = sev_colors.get(sev, "#7f8c8d")
        return (
            f'<span style="background:{color};color:#fff;'
            f'padding:2px 8px;border-radius:3px;font-size:0.85em">{sev}</span>'
        )

    rows_html = ""
    if not summary_only:
        for f in findings[:top_n]:
            mcc_mnc = f"{f['mcc']}-{f['mnc']}" if f["mcc"] and f["mnc"] else ""
            ev = (f["evidence"] or "")[:120]
            rows_html += (
                f"<tr>"
                f"<td>{badge(f['severity'])}</td>"
                f"<td>{f['operator'] or ''}</td>"
                f"<td>{mcc_mnc}</td>"
                f"<td>{f['control_ref'] or ''}</td>"
                f"<td>{f['title'] or ''}</td>"
                f"<td><small>{ev}</small></td>"
                f"</tr>\n"
            )

    summary_rows = "".join(
        f"<tr><td>{badge(sev)}</td><td>{summary['counts'].get(sev, 0)}</td></tr>"
        for sev in SEVERITY_ORDER
    )
    top_op_rows = "".join(
        f"<tr><td>{op}</td><td>{score}</td></tr>"
        for op, score in summary["top_operators"]
    )

    findings_section = ""
    if not summary_only:
        findings_section = f"""
        <h2>Findings ({min(len(findings), top_n)} shown)</h2>
        <table>
          <thead>
            <tr>
              <th>Severity</th><th>Operator</th><th>MCC-MNC</th>
              <th>Control Ref</th><th>Title</th><th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>3GPP Security Baseline Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #222; }}
    h1 {{ border-bottom: 2px solid #333; padding-bottom: .4rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
    th, td {{ border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; vertical-align: top; }}
    th {{ background: #f5f5f5; }}
    tr:nth-child(even) {{ background: #fafafa; }}
    small {{ color: #555; word-break: break-all; }}
  </style>
</head>
<body>
  <h1>3GPP Security Baseline Report</h1>
  <p><em>Generated: {ts}</em> &mdash; Total findings: <strong>{summary['total']}</strong></p>

  <h2>Executive Summary</h2>
  <div style="display:flex;gap:2rem;flex-wrap:wrap">
    <div>
      <h3>Findings by Severity</h3>
      <table style="width:auto">
        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
        <tbody>{summary_rows}</tbody>
      </table>
    </div>
    <div>
      <h3>Top Operators by Risk Weight</h3>
      <table style="width:auto">
        <thead><tr><th>Operator</th><th>Score</th></tr></thead>
        <tbody>{top_op_rows}</tbody>
      </table>
    </div>
  </div>
  {findings_section}
</body>
</html>
"""


FORMATTERS = {
    "text":     generate_text,
    "json":     generate_json,
    "markdown": generate_markdown,
    "html":     generate_html,
}


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GSMA FS.31 / ETSI Security Baseline Scoring & Compliance Report"
    )
    parser.add_argument("--db", default="database.db",
                        help="Path to SQLite database (default: database.db)")
    parser.add_argument("--format", choices=list(FORMATTERS), default="text",
                        help="Output format: text | json | markdown | html (default: text)")
    parser.add_argument("--output", metavar="FILE",
                        help="Write report to FILE instead of stdout")
    parser.add_argument("--operator", metavar="SUBSTR",
                        help="Filter findings to operators matching this substring")
    parser.add_argument("--severity-min", metavar="SEV", default="INFO",
                        choices=SEVERITY_ORDER,
                        help="Minimum severity to include (default: INFO)")
    parser.add_argument("--top-n", type=int, default=20,
                        help="Max findings in detail section (default: 20)")
    parser.add_argument("--collect", action="store_true",
                        help="Run all collect_* functions and save before reporting")
    parser.add_argument("--summary-only", action="store_true",
                        help="Show only the executive summary, no per-finding detail")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        log.error("Database %s not found.", db_path)
        sys.exit(1)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)

    if args.collect:
        log.info("Running all collection functions...")
        all_findings: list[dict] = []
        all_findings.extend(collect_tls_findings(conn))
        all_findings.extend(collect_ike_findings(conn))
        all_findings.extend(collect_5gc_findings(conn))
        all_findings.extend(collect_missing_service_findings(conn))
        all_findings.extend(collect_diameter_findings(conn))
        all_findings.extend(collect_rsp_findings(conn))
        all_findings.extend(collect_ct_findings(conn))

        n = save_findings(conn, all_findings)
        log.info("Saved %d findings to risk_findings.", n)

    findings = load_findings(conn, args.operator, args.severity_min)
    conn.close()

    if not findings and not args.collect:
        log.warning(
            "No findings in risk_findings table. "
            "Run with --collect to populate from DB signals."
        )

    formatter = FORMATTERS[args.format]
    report = formatter(findings, args.top_n, args.summary_only)

    if args.output:
        out = Path(args.output)
        out.write_text(report, encoding="utf-8")
        log.info("Report written to %s", out)
    else:
        print(report)


if __name__ == "__main__":
    main()
