#!/usr/bin/env python3
"""
eSIM RSP (Remote SIM Provisioning) Discovery & Fingerprinting
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Standards: GSMA SGP.22 (Consumer eSIM), SGP.02 (M2M eSIM)

ARCHITECTURE CONTEXT
─────────────────────
RSP endpoints are internet-facing by design — unlike most 3GPP
infrastructure which lives behind GRX/IPX private networks.

  SM-DP+ (Subscription Manager Data Preparation+)
    Stores operator profiles, activates eSIMs.
    End-to-end TLS to the LPA on the device (ES9+ interface).
    Reachable from: public internet ✅

  SM-DS (Subscription Manager Discovery Service)
    Directory service — device contacts SM-DS to discover which
    SM-DP+ has a pending profile.  One SM-DS can serve many operators.
    GSMA operates a root SM-DS: lpa.ds.gsma.com
    Reachable from: public internet ✅

  LPA (Local Profile Assistant) proxy / gateway
    Some operators expose LPA-side endpoints publicly.

DNS DISCOVERY STRATEGY
───────────────────────
1. Per-operator DNS probing under pub.3gppnetwork.org
   Pattern: smdp.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
   Also tried: smdp+, smds, rsp, lpa under the same base

2. Known reference endpoints (always probed):
   - gsma.smds.com            GSMA root SM-DS
   - prod.smds.rsp.goog       Google SM-DS (for Pixel / Android)
   - lpa.ds.gsma.com          GSMA CI root SM-DS

ACTIVE PROBING (--active)
──────────────────────────
When enabled, performs HTTPS POST to ES9+ initiateAuthentication
endpoint per SGP.22 §5.6.1:
  POST /gsma/rsp2/es9plus/initiateAuthentication
  Content-Type: application/json

HTTP status and X-Admin-Protocol header reveal:
  - Whether the server is a live RSP platform
  - SGP.22 version (e.g. "gsma/rsp/v2.0.0")
  - Vendor via TLS certificate CN/O fields

VENDOR FINGERPRINTING
──────────────────────
From TLS subject/issuer:
  THALES / GEMALTO / CINTERION → Thales
  IDEMIA / OBERTHUR             → IDEMIA
  G+D / GIESECKE                → G+D
  VALID                         → Valid
  STMICRO                       → STMicro
  APPLE                         → Apple

Usage:
  # DNS-only discovery (safe, passive)
  python3 3gpppub-rsp-discovery.py

  # Active HTTPS probing + TLS fingerprinting
  python3 3gpppub-rsp-discovery.py --active

  # Use local DB as operator source (faster, offline)
  python3 3gpppub-rsp-discovery.py --source database.db

  # Limit to first N operators (useful for testing)
  python3 3gpppub-rsp-discovery.py --limit 200

  # Summary only (no new scanning)
  python3 3gpppub-rsp-discovery.py --summary-only
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import sqlite3
import ssl
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import requests
from dns.resolver import NXDOMAIN, NoAnswer, Timeout

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("rsp-scan.log"),
    ],
)
log = logging.getLogger(__name__)

MCC_MNC_URL = (
    "https://raw.githubusercontent.com/pbakondy/mcc-mnc-list/master/mcc-mnc-list.json"
)

# Known global / shared RSP infrastructure — always probed regardless of operator list
KNOWN_RSP_ENDPOINTS = [
    ("gsma.smds.com",       "SM-DS", "GSMA"),
    ("prod.smds.rsp.goog",  "SM-DS", "Google"),
    ("lpa.ds.gsma.com",     "SM-DS", "GSMA"),
]

# ── Database schema ────────────────────────────────────────────────────────────

SCHEMA_RSP = """
CREATE TABLE IF NOT EXISTS rsp_endpoints (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    operator         TEXT,
    country_name     TEXT,
    mnc              INTEGER,
    mcc              INTEGER,
    fqdn             TEXT    NOT NULL,
    role             TEXT,
    resolved_ips     TEXT,
    https_reachable  INTEGER DEFAULT 0,
    http_status      INTEGER,
    vendor           TEXT,
    tls_subject      TEXT,
    tls_issuer       TEXT,
    tls_san          TEXT,
    sgp22_version    TEXT,
    discovery_method TEXT,
    first_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fqdn)
);
CREATE INDEX IF NOT EXISTS idx_rsp_country  ON rsp_endpoints(country_name);
CREATE INDEX IF NOT EXISTS idx_rsp_role     ON rsp_endpoints(role);
CREATE INDEX IF NOT EXISTS idx_rsp_vendor   ON rsp_endpoints(vendor);
CREATE INDEX IF NOT EXISTS idx_rsp_operator ON rsp_endpoints(operator);
"""

# ── FQDN candidate generation ──────────────────────────────────────────────────

def build_rsp_candidates(mnc: int, mcc: int) -> list[tuple[str, str, str]]:
    """
    Return a list of (fqdn, role, discovery_method) tuples to probe
    for a given MCC-MNC pair.
    """
    mnc3     = f"{mnc:03d}"
    mcc3     = f"{mcc:03d}"
    base_pub = f"mnc{mnc3}.mcc{mcc3}.pub.3gppnetwork.org"

    return [
        (f"smdp.{base_pub}",  "SM-DP+",  "dns_pub"),
        # Note: bare '+' is not a valid DNS label; use hyphenated form.
        (f"smdp-plus.{base_pub}", "SM-DP+",  "dns_pub"),
        (f"smds.{base_pub}",  "SM-DS",   "dns_pub"),
        (f"rsp.{base_pub}",   "unknown", "dns_pub"),
        (f"lpa.{base_pub}",   "SM-DP+",  "dns_pub"),
    ]


# ── DNS resolution ─────────────────────────────────────────────────────────────

def make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout  = 3
    r.lifetime = 6
    return r


_resolver = None


def get_resolver() -> dns.resolver.Resolver:
    global _resolver
    if _resolver is None:
        _resolver = make_resolver()
    return _resolver


def resolve_fqdn(fqdn: str, retries: int = 1) -> list[str]:
    resolver = get_resolver()
    for attempt in range(retries + 1):
        try:
            answers = resolver.resolve(fqdn, "A")
            return [r.address for r in answers]
        except (NXDOMAIN, NoAnswer):
            return []
        except Timeout:
            if attempt < retries:
                time.sleep(0.3)
            return []
        except Exception:
            return []
    return []


# ── TLS certificate helpers ────────────────────────────────────────────────────

def fetch_tls_cert(hostname: str, port: int = 443, timeout: int = 8) -> dict:
    """
    Connect to hostname:port and return a dict with subject, issuer, san fields.
    Returns empty dict on any error.

    Note: with CERT_NONE, getpeercert() returns {} even when a cert was
    presented. Always decode DER via binary_form=True.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                raw = ssock.getpeercert() or {}
                cert_bin = ssock.getpeercert(binary_form=True)
                if not raw and cert_bin:
                    # Reuse TLS probe helper when available; otherwise local decode.
                    try:
                        from importlib import import_module
                        tls_mod = import_module("3gpppub-tls-ike-probe")  # type: ignore
                        raw = tls_mod.decode_peer_cert(cert_bin)
                    except Exception:
                        import os
                        import tempfile
                        pem = ssl.DER_cert_to_PEM_cert(cert_bin)
                        fd, path = tempfile.mkstemp(suffix=".pem")
                        try:
                            with os.fdopen(fd, "w", encoding="ascii") as fh:
                                fh.write(pem)
                            raw = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
                        finally:
                            try:
                                os.unlink(path)
                            except OSError:
                                pass
                if not raw:
                    return {}
                # Subject
                subject = dict(x[0] for x in raw.get("subject", ()))
                # Issuer
                issuer  = dict(x[0] for x in raw.get("issuer", ()))
                # SAN
                san_list = [
                    v for typ, v in raw.get("subjectAltName", ()) if typ == "DNS"
                ]
                return {
                    "subject": subject.get("commonName", "") or subject.get("organizationName", ""),
                    "issuer":  issuer.get("organizationName", "") or issuer.get("commonName", ""),
                    "san":     ",".join(san_list),
                }
    except Exception:
        return {}


def fingerprint_vendor(tls_subject: str, tls_issuer: str) -> str | None:
    """Identify RSP platform vendor from TLS cert fields."""
    combined = (tls_subject + " " + tls_issuer).upper()
    if any(k in combined for k in ("THALES", "GEMALTO", "CINTERION")):
        return "Thales"
    if any(k in combined for k in ("IDEMIA", "OBERTHUR")):
        return "IDEMIA"
    if any(k in combined for k in ("G+D", "GIESECKE")):
        return "G+D"
    if "VALID" in combined:
        return "Valid"
    if "STMICRO" in combined:
        return "STMicro"
    if "APPLE" in combined:
        return "Apple"
    return None


# ── HTTPS active probe ─────────────────────────────────────────────────────────

ES9PLUS_PATH = "/gsma/rsp2/es9plus/initiateAuthentication"
PROBE_BODY    = b"{}"


def https_probe(fqdn: str, timeout: int = 8) -> dict:
    """
    POST to the SGP.22 ES9+ initiateAuthentication endpoint.
    Returns a dict with: https_reachable, http_status, sgp22_version, vendor,
    tls_subject, tls_issuer, tls_san.
    """
    result: dict = {
        "https_reachable": 0,
        "http_status":     None,
        "sgp22_version":   None,
        "vendor":          None,
        "tls_subject":     None,
        "tls_issuer":      None,
        "tls_san":         None,
    }

    # Grab TLS cert first (independent of HTTP probe)
    cert = fetch_tls_cert(fqdn, port=443, timeout=timeout)
    if cert:
        result["tls_subject"] = cert.get("subject")
        result["tls_issuer"]  = cert.get("issuer")
        result["tls_san"]     = cert.get("san")
        result["vendor"]      = fingerprint_vendor(
            cert.get("subject", ""), cert.get("issuer", "")
        )

    # HTTP probe
    url = f"https://{fqdn}{ES9PLUS_PATH}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        data=PROBE_BODY,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "gsma-rsp-lpa/1.0",
        },
    )
    try:
        handler = urllib.request.HTTPSHandler(context=ctx)
        opener  = urllib.request.build_opener(handler)
        with opener.open(req, timeout=timeout) as resp:
            result["https_reachable"] = 1
            result["http_status"]     = resp.status
            # SGP.22 version from X-Admin-Protocol header
            proto = resp.headers.get("X-Admin-Protocol", "")
            if proto:
                result["sgp22_version"] = proto
    except urllib.error.HTTPError as exc:
        result["https_reachable"] = 1          # server replied — it exists
        result["http_status"]     = exc.code
        proto = exc.headers.get("X-Admin-Protocol", "")
        if proto:
            result["sgp22_version"] = proto
    except Exception:
        pass

    return result


# ── Per-operator probe ─────────────────────────────────────────────────────────

def probe_operator_rsp(
    item: dict,
    active: bool,
    http_timeout: int,
) -> dict:
    """Probe a single operator's RSP FQDNs. Returns a results dict."""
    try:
        mcc = int(item["mcc"])
        mnc = int(item["mnc"])
    except (KeyError, ValueError):
        return {}

    operator     = item.get("operator",    item.get("brand",   "Unknown"))
    country_name = item.get("countryName", item.get("country", "Unknown"))

    candidates = build_rsp_candidates(mnc, mcc)
    found      = []

    for fqdn, role, method in candidates:
        ips = resolve_fqdn(fqdn)
        if not ips:
            continue

        entry: dict = {
            "fqdn":             fqdn,
            "role":             role,
            "resolved_ips":     ",".join(ips),
            "discovery_method": method,
            "https_reachable":  0,
            "http_status":      None,
            "vendor":           None,
            "tls_subject":      None,
            "tls_issuer":       None,
            "tls_san":          None,
            "sgp22_version":    None,
        }

        log.info("  [DNS] [+] %s  role=%s  IPs=%s", fqdn, role, ", ".join(ips))

        if active:
            probe = https_probe(fqdn, timeout=http_timeout)
            entry.update(probe)
            if entry["https_reachable"]:
                log.info(
                    "  [HTTPS] [+] %s  status=%s  sgp22=%s  vendor=%s",
                    fqdn,
                    entry["http_status"],
                    entry["sgp22_version"],
                    entry["vendor"],
                )

        found.append(entry)

    return {
        "mnc":          mnc,
        "mcc":          mcc,
        "operator":     operator,
        "country_name": country_name,
        "found":        found,
    }


# ── Known reference endpoint probe ────────────────────────────────────────────

def probe_known_endpoints(active: bool, http_timeout: int) -> list[dict]:
    """
    Probe the global/shared RSP reference endpoints that are not tied
    to a specific MCC-MNC pair.
    """
    results = []
    for fqdn, role, operator in KNOWN_RSP_ENDPOINTS:
        ips = resolve_fqdn(fqdn)
        entry: dict = {
            "mnc":              None,
            "mcc":              None,
            "operator":         operator,
            "country_name":     None,
            "fqdn":             fqdn,
            "role":             role,
            "resolved_ips":     ",".join(ips) if ips else None,
            "discovery_method": "known_reference",
            "https_reachable":  0,
            "http_status":      None,
            "vendor":           None,
            "tls_subject":      None,
            "tls_issuer":       None,
            "tls_san":          None,
            "sgp22_version":    None,
        }

        if ips:
            log.info("  [KNOWN] [+] %s  role=%s  IPs=%s", fqdn, role, ", ".join(ips))
        else:
            log.info("  [KNOWN] [-] %s  no DNS response", fqdn)

        if active:
            probe = https_probe(fqdn, timeout=http_timeout)
            entry.update(probe)
            if entry["https_reachable"]:
                log.info(
                    "  [KNOWN][HTTPS] %s  status=%s  sgp22=%s  vendor=%s",
                    fqdn,
                    entry["http_status"],
                    entry["sgp22_version"],
                    entry["vendor"],
                )

        results.append(entry)
    return results


# ── Database helpers ───────────────────────────────────────────────────────────

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_RSP)
    conn.commit()
    return conn


def save_rsp_result(conn: sqlite3.Connection, result: dict) -> None:
    if not result or not result.get("found"):
        return
    with conn:
        for entry in result["found"]:
            conn.execute(
                """
                INSERT INTO rsp_endpoints
                    (operator, country_name, mnc, mcc,
                     fqdn, role, resolved_ips,
                     https_reachable, http_status,
                     vendor, tls_subject, tls_issuer, tls_san,
                     sgp22_version, discovery_method, first_seen)
                VALUES
                    (:operator, :country_name, :mnc, :mcc,
                     :fqdn, :role, :resolved_ips,
                     :https_reachable, :http_status,
                     :vendor, :tls_subject, :tls_issuer, :tls_san,
                     :sgp22_version, :discovery_method,
                     :first_seen)
                ON CONFLICT(fqdn) DO UPDATE SET
                    resolved_ips    = excluded.resolved_ips,
                    https_reachable = excluded.https_reachable,
                    http_status     = excluded.http_status,
                    vendor          = COALESCE(excluded.vendor, vendor),
                    tls_subject     = COALESCE(excluded.tls_subject, tls_subject),
                    tls_issuer      = COALESCE(excluded.tls_issuer, tls_issuer),
                    tls_san         = COALESCE(excluded.tls_san, tls_san),
                    sgp22_version   = COALESCE(excluded.sgp22_version, sgp22_version)
                """,
                {
                    "operator":         result["operator"],
                    "country_name":     result["country_name"],
                    "mnc":              result["mnc"],
                    "mcc":              result["mcc"],
                    "fqdn":             entry["fqdn"],
                    "role":             entry["role"],
                    "resolved_ips":     entry["resolved_ips"],
                    "https_reachable":  entry["https_reachable"],
                    "http_status":      entry["http_status"],
                    "vendor":           entry["vendor"],
                    "tls_subject":      entry["tls_subject"],
                    "tls_issuer":       entry["tls_issuer"],
                    "tls_san":          entry["tls_san"],
                    "sgp22_version":    entry["sgp22_version"],
                    "discovery_method": entry["discovery_method"],
                    "first_seen":       datetime.now(timezone.utc).isoformat(),
                },
            )


def save_known_results(conn: sqlite3.Connection, entries: list[dict]) -> None:
    for entry in entries:
        with conn:
            conn.execute(
                """
                INSERT INTO rsp_endpoints
                    (operator, country_name, mnc, mcc,
                     fqdn, role, resolved_ips,
                     https_reachable, http_status,
                     vendor, tls_subject, tls_issuer, tls_san,
                     sgp22_version, discovery_method, first_seen)
                VALUES
                    (:operator, :country_name, :mnc, :mcc,
                     :fqdn, :role, :resolved_ips,
                     :https_reachable, :http_status,
                     :vendor, :tls_subject, :tls_issuer, :tls_san,
                     :sgp22_version, :discovery_method,
                     :first_seen)
                ON CONFLICT(fqdn) DO UPDATE SET
                    resolved_ips    = excluded.resolved_ips,
                    https_reachable = excluded.https_reachable,
                    http_status     = excluded.http_status,
                    vendor          = COALESCE(excluded.vendor, vendor),
                    tls_subject     = COALESCE(excluded.tls_subject, tls_subject),
                    tls_issuer      = COALESCE(excluded.tls_issuer, tls_issuer),
                    tls_san         = COALESCE(excluded.tls_san, tls_san),
                    sgp22_version   = COALESCE(excluded.sgp22_version, sgp22_version)
                """,
                {**entry, "first_seen": datetime.now(timezone.utc).isoformat()},
            )


# ── Operator loading ───────────────────────────────────────────────────────────

def load_operators(source: str) -> list[dict]:
    """
    Load operator list from a URL (JSON), local JSON file, or SQLite DB.
    When source is a .db file the operators table is used.
    """
    if source.endswith(".db") or (not source.startswith("http") and Path(source).suffix == ".db"):
        conn = sqlite3.connect(source)
        conn.row_factory = sqlite3.Row
        cols = {r[1] for r in conn.execute("PRAGMA table_info(operators)").fetchall()}
        country_expr = (
            "COALESCE(country_name, '') AS countryName"
            if "country_name" in cols
            else "'' AS countryName"
        )
        rows = conn.execute(
            f"SELECT mnc, mcc, operator AS operator, {country_expr} FROM operators"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    if source.startswith("http"):
        resp = requests.get(source, timeout=30)
        resp.raise_for_status()
        return resp.json()
    with open(source) as f:
        return json.load(f)


# ── Summary ────────────────────────────────────────────────────────────────────

def print_summary(conn: sqlite3.Connection) -> None:
    total = conn.execute("SELECT COUNT(*) FROM rsp_endpoints").fetchone()[0]

    print(f"\n{'═'*68}")
    print("  eSIM RSP Discovery Summary  (GSMA SGP.22 / SGP.02)")
    print(f"{'═'*68}")

    if total == 0:
        print("  No RSP endpoints found.")
        print("  Tip: run without --summary-only to start a scan.")
        return

    print(f"  Total RSP endpoints:  {total}")

    https_cnt = conn.execute(
        "SELECT COUNT(*) FROM rsp_endpoints WHERE https_reachable = 1"
    ).fetchone()[0]
    print(f"  HTTPS reachable:      {https_cnt}")

    print("\n── By Role ──────────────────────────────────────────────────────")
    role_rows = conn.execute(
        "SELECT role, COUNT(*) FROM rsp_endpoints GROUP BY role ORDER BY COUNT(*) DESC"
    ).fetchall()
    for role, cnt in role_rows:
        print(f"  {(role or 'unknown'):<20} {cnt:>5} endpoints")

    print("\n── By Vendor ────────────────────────────────────────────────────")
    vendor_rows = conn.execute(
        """
        SELECT COALESCE(vendor, 'unknown') AS v, COUNT(*) AS cnt
        FROM rsp_endpoints GROUP BY v ORDER BY cnt DESC
        """
    ).fetchall()
    for v, cnt in vendor_rows:
        print(f"  {v:<20} {cnt:>5}")

    print("\n── By SGP.22 Version ────────────────────────────────────────────")
    ver_rows = conn.execute(
        """
        SELECT COALESCE(sgp22_version, 'not probed / unknown') AS v, COUNT(*) AS cnt
        FROM rsp_endpoints GROUP BY v ORDER BY cnt DESC
        """
    ).fetchall()
    for v, cnt in ver_rows:
        print(f"  {v:<35} {cnt:>5}")

    print("\n── Top Countries ────────────────────────────────────────────────")
    ctry_rows = conn.execute(
        """
        SELECT COALESCE(country_name, 'N/A') AS country,
               COUNT(DISTINCT COALESCE(mcc || '-' || mnc, fqdn)) AS operators,
               COUNT(*) AS endpoints
        FROM rsp_endpoints
        GROUP BY country
        ORDER BY endpoints DESC LIMIT 15
        """
    ).fetchall()
    for country, operators, endpoints in ctry_rows:
        print(f"  {country:<35} {operators:>3} ops  {endpoints:>4} endpoints")

    print("\n── HTTPS-Reachable RSP Endpoints ────────────────────────────────")
    live_rows = conn.execute(
        """
        SELECT operator, country_name, fqdn, role, vendor,
               http_status, sgp22_version, resolved_ips
        FROM rsp_endpoints
        WHERE https_reachable = 1
        ORDER BY country_name, operator
        """
    ).fetchall()
    if live_rows:
        for row in live_rows:
            vendor  = row["vendor"]  or "?"
            version = row["sgp22_version"] or ""
            print(
                f"  [{row['role']:<7}] {(row['country_name'] or 'N/A'):<22}"
                f" {(row['operator'] or 'N/A'):<30}"
                f" {row['fqdn']}"
                f"  status={row['http_status']}"
                f"  vendor={vendor}"
                f"  {version}"
            )
    else:
        print("  (none — run with --active to perform HTTPS probing)")

    print(f"\n{'═'*68}\n")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover eSIM RSP (SM-DP+/SM-DS) endpoints via DNS and optional HTTPS probing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Standards:
  GSMA SGP.22 — Consumer eSIM Remote SIM Provisioning
  GSMA SGP.02 — M2M eSIM Remote SIM Provisioning

Discovery methods:
  DNS (always)  — probes smdp/smdp+/smds/rsp/lpa under pub.3gppnetwork.org
  Known refs    — probes GSMA and Google shared SM-DS endpoints
  HTTPS probe   — active ES9+ initiateAuthentication POST (requires --active)
        """,
    )
    parser.add_argument(
        "--db", default="database.db",
        help="SQLite database path (default: database.db)",
    )
    parser.add_argument(
        "--source", default=MCC_MNC_URL,
        help="Operator source: URL, local JSON, or .db file (default: GitHub MCC-MNC list)",
    )
    parser.add_argument(
        "--workers", type=int, default=15,
        help="Concurrent DNS/probe workers (default: 15)",
    )
    parser.add_argument(
        "--timeout", type=int, default=8,
        help="HTTPS probe timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "--active", action="store_true",
        help="Enable active HTTPS probing (ES9+ endpoint + TLS fingerprinting)",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Limit number of operators scanned (useful for testing)",
    )
    parser.add_argument(
        "--summary-only", action="store_true",
        help="Print summary from existing DB and exit",
    )
    args = parser.parse_args()

    conn = init_db(args.db)

    if args.summary_only:
        print_summary(conn)
        conn.close()
        return

    if args.active:
        log.info("Active HTTPS probing ENABLED — will POST to ES9+ endpoint and grab TLS certs")
    else:
        log.info("Passive DNS-only mode (use --active for HTTPS probing)")

    # Always probe known reference endpoints first
    log.info("Probing %d known RSP reference endpoints...", len(KNOWN_RSP_ENDPOINTS))
    known_results = probe_known_endpoints(active=args.active, http_timeout=args.timeout)
    save_known_results(conn, known_results)

    # Load per-operator list
    log.info("Loading operator list from: %s", args.source)
    operators = load_operators(args.source)
    if args.limit:
        operators = operators[: args.limit]
        log.info("Limiting scan to first %d operators", args.limit)

    total = len(operators)
    log.info("Loaded %d operators — starting RSP DNS scan with %d workers", total, args.workers)

    completed = found_ops = 0
    start     = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                probe_operator_rsp, item, args.active, args.timeout
            ): item
            for item in operators
        }

        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                if result and result.get("found"):
                    save_rsp_result(conn, result)
                    found_ops += 1
                    roles = ", ".join(
                        f"{e['role']}({e.get('vendor') or 'dns-only'})"
                        for e in result["found"]
                    )
                    log.info(
                        "[%d/%d] RSP found — %s (%s): %s",
                        completed, total,
                        result["operator"], result["country_name"], roles,
                    )
                elif completed % 500 == 0:
                    elapsed = time.time() - start
                    eta     = (total - completed) / max(completed / elapsed, 0.01)
                    log.info(
                        "[%d/%d] ETA %.0fs | RSP operators found so far: %d",
                        completed, total, eta, found_ops,
                    )
            except Exception as exc:
                log.debug("Worker error: %s", exc)

    elapsed = time.time() - start
    log.info(
        "RSP scan done in %.1fs | %d operators with RSP endpoints discovered",
        elapsed, found_ops,
    )
    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
