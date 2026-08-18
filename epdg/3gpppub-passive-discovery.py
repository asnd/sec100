#!/usr/bin/env python3
"""
Passive Host Discovery via Certificate Transparency + Passive DNS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PURPOSE
───────
Discover 3GPP-related hostnames that are NOT in the predefined SUBDOMAINS
list by querying two passive, read-only data sources:

  1. Certificate Transparency logs (crt.sh)
     Operators sometimes obtain TLS certificates for 3GPP endpoints.
     These certificates are logged publicly by CAs, leaking FQDNs that
     would otherwise only be discovered by active DNS enumeration.

  2. HackerTarget Passive DNS
     Aggregated DNS observation data from passive sensors.  Returns
     hostnames seen resolving under 3gppnetwork.org without any active
     probing from our side.

PASSIVE GUARANTEE
─────────────────
No packets are sent to any 3GPP endpoint.  All HTTP requests go only
to third-party intelligence services (crt.sh, api.hackertarget.com).

FQDN CLASSIFICATION
────────────────────
Each discovered FQDN is parsed against the canonical pattern:

  {prefix}.mnc{MNC}.mcc{MCC}.{zone}.3gppnetwork.org

  in_predefined    — prefix is in the known SUBDOMAINS list
  is_new_candidate — NOT in_predefined AND zone == "pub"
                     (pub zone is operator-facing internet; novel prefixes
                      here represent genuinely unknown public services)

OPERATOR ENRICHMENT
────────────────────
For each parsed FQDN the operators table in the database is queried to
attach operator name and country — same enrichment used by the active
scanner.

DATABASE
────────
Results are stored in the discovered_hosts table (created if absent).
The UNIQUE(source, fqdn) constraint ensures idempotent re-runs; each
run safely inserts new rows and silently ignores duplicates.

Usage:
  # Query both sources, save to database.db
  python3 3gpppub-passive-discovery.py

  # Limit crt.sh results to first 500 entries
  python3 3gpppub-passive-discovery.py --limit 500

  # Only print summary of existing data, no HTTP queries
  python3 3gpppub-passive-discovery.py --summary-only

  # Use a different database file
  python3 3gpppub-passive-discovery.py --db /data/scan.db
"""

from __future__ import annotations

import argparse
import logging
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone

import requests

import subdomains as subdomains_module

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("passive-discovery.log"),
    ],
)
log = logging.getLogger(__name__)

# ── External data source URLs ─────────────────────────────────────────────────

CRTSH_URL      = "https://crt.sh/?q=%25.3gppnetwork.org&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q=3gppnetwork.org"

# ── FQDN parse pattern ────────────────────────────────────────────────────────

FQDN_RE = re.compile(
    r"^(?P<prefix>.+?)\.mnc(?P<mnc>\d{1,3})\.mcc(?P<mcc>\d{1,3})\."
    r"(?P<zone>[a-z0-9]+)\.3gppnetwork\.org$",
    re.IGNORECASE,
)

# ── Database schema ───────────────────────────────────────────────────────────

SCHEMA_PASSIVE = """
CREATE TABLE IF NOT EXISTS discovered_hosts (
    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
    source            TEXT     NOT NULL,
    fqdn              TEXT     NOT NULL,
    service_prefix    TEXT,
    zone              TEXT,
    in_predefined     INTEGER  DEFAULT 0,
    is_new_candidate  INTEGER  DEFAULT 0,
    mnc               INTEGER,
    mcc               INTEGER,
    operator          TEXT,
    country_name      TEXT,
    cert_id           TEXT,
    first_seen        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source, fqdn)
);
CREATE INDEX IF NOT EXISTS idx_ph_source    ON discovered_hosts(source);
CREATE INDEX IF NOT EXISTS idx_ph_zone      ON discovered_hosts(zone);
CREATE INDEX IF NOT EXISTS idx_ph_prefix    ON discovered_hosts(service_prefix);
CREATE INDEX IF NOT EXISTS idx_ph_candidate ON discovered_hosts(is_new_candidate);
"""


# ── Database helpers ──────────────────────────────────────────────────────────

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PASSIVE)
    conn.commit()
    log.info("Database initialised: %s", db_path)
    return conn


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def enrich_from_db(conn: sqlite3.Connection, mnc: int, mcc: int) -> tuple[str | None, str | None]:
    """Return (operator, country_name) from the operators table for the given MNC/MCC."""
    if not _table_exists(conn, "operators"):
        return None, None

    # country_name may be absent on older schemas — select what exists.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(operators)").fetchall()}
    country_expr = "country_name" if "country_name" in cols else "NULL AS country_name"
    row = conn.execute(
        f"SELECT operator, {country_expr} FROM operators WHERE mnc = ? AND mcc = ? LIMIT 1",
        (mnc, mcc),
    ).fetchone()
    if row:
        return row["operator"], row["country_name"]
    return None, None


def save_hosts(conn: sqlite3.Connection, records: list[dict]) -> int:
    """Insert records using ON CONFLICT DO NOTHING; return count of new rows."""
    inserted = 0
    with conn:
        for rec in records:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO discovered_hosts
                    (source, fqdn, service_prefix, zone, in_predefined,
                     is_new_candidate, mnc, mcc, operator, country_name,
                     cert_id, first_seen)
                VALUES
                    (:source, :fqdn, :service_prefix, :zone, :in_predefined,
                     :is_new_candidate, :mnc, :mcc, :operator, :country_name,
                     :cert_id, :first_seen)
                """,
                rec,
            )
            inserted += cur.rowcount
    return inserted


# ── Data-source queries ───────────────────────────────────────────────────────

def query_crt_sh(limit: int = 0) -> list[tuple[str, str]]:
    """Query Certificate Transparency logs via crt.sh.

    Returns a list of (fqdn, cert_id) tuples.  Wildcard names have their
    leading ``*.`` stripped.  When *limit* > 0 only the first *limit* unique
    FQDNs are returned.
    """
    log.info("Querying crt.sh …")
    try:
        resp = requests.get(CRTSH_URL, timeout=60)
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.error("crt.sh request failed: %s", exc)
        return []

    try:
        data = resp.json()
    except ValueError as exc:
        log.error("crt.sh JSON parse error: %s", exc)
        return []

    seen: dict[str, str] = {}  # fqdn -> cert_id (first occurrence wins)
    for entry in data:
        cert_id  = str(entry.get("id", ""))
        name_val = entry.get("name_value", "")
        for raw in name_val.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            # Strip wildcard prefix
            fqdn = raw.lstrip("*").lstrip(".")
            if fqdn and fqdn not in seen:
                seen[fqdn] = cert_id

    results = list(seen.items())
    log.info("crt.sh returned %d unique FQDNs", len(results))

    if limit > 0:
        results = results[:limit]
        log.info("Limiting crt.sh results to %d entries", limit)

    return results


def query_hackertarget() -> list[str]:
    """Query HackerTarget passive DNS for 3gppnetwork.org.

    Returns a list of hostnames (the portion before the comma in each
    ``hostname,ip`` response line).
    """
    log.info("Querying HackerTarget passive DNS …")
    try:
        resp = requests.get(HACKERTARGET_URL, timeout=60)
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.error("HackerTarget request failed: %s", exc)
        return []

    text = resp.text.strip()
    if not text or text.startswith("error"):
        log.warning("HackerTarget returned no data or an error: %r", text[:120])
        return []

    fqdns: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        fqdn = line.split(",", 1)[0].strip()
        if fqdn and fqdn not in seen:
            seen.add(fqdn)
            fqdns.append(fqdn)

    log.info("HackerTarget returned %d unique FQDNs", len(fqdns))
    return fqdns


# ── FQDN parsing & classification ────────────────────────────────────────────

def parse_fqdn(fqdn: str) -> dict | None:
    """Parse a 3GPP FQDN and return a classification dict, or None if it does
    not match the canonical pattern."""
    m = FQDN_RE.match(fqdn)
    if not m:
        return None
    prefix = m.group("prefix").lower()
    mnc    = int(m.group("mnc"))
    mcc    = int(m.group("mcc"))
    zone   = m.group("zone").lower()

    in_predefined   = int(prefix in subdomains_module.SUBDOMAINS)
    is_new_candidate = int(not in_predefined and zone == "pub")

    return {
        "service_prefix":  prefix,
        "zone":            zone,
        "mnc":             mnc,
        "mcc":             mcc,
        "in_predefined":   in_predefined,
        "is_new_candidate": is_new_candidate,
    }


# ── Main pipeline ─────────────────────────────────────────────────────────────

def build_records(
    conn: sqlite3.Connection,
    crt_entries: list[tuple[str, str]],
    ht_fqdns: list[str],
) -> list[dict]:
    """Deduplicate, parse, classify, and enrich all discovered FQDNs.

    Returns a list of record dicts ready for database insertion.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Merge into a unified set: fqdn -> {source, cert_id}
    # If a FQDN appears in both sources, we emit one record per source so the
    # UNIQUE(source, fqdn) constraint is respected and both attributions are kept.
    per_source: dict[str, list[tuple[str, str]]] = {"crt.sh": [], "hackertarget": []}
    for fqdn, cert_id in crt_entries:
        per_source["crt.sh"].append((fqdn, cert_id))
    for fqdn in ht_fqdns:
        per_source["hackertarget"].append((fqdn, ""))

    # Operator enrichment cache to avoid redundant DB hits
    enrich_cache: dict[tuple[int, int], tuple[str | None, str | None]] = {}
    records: list[dict] = []

    for source, entries in per_source.items():
        seen_in_source: set[str] = set()
        for fqdn, cert_id in entries:
            fqdn_lower = fqdn.lower()
            if fqdn_lower in seen_in_source:
                continue
            seen_in_source.add(fqdn_lower)

            parsed = parse_fqdn(fqdn_lower)
            if parsed is None:
                # FQDN does not match canonical 3GPP pattern — store minimally
                records.append({
                    "source":          source,
                    "fqdn":            fqdn_lower,
                    "service_prefix":  None,
                    "zone":            None,
                    "in_predefined":   0,
                    "is_new_candidate": 0,
                    "mnc":             None,
                    "mcc":             None,
                    "operator":        None,
                    "country_name":    None,
                    "cert_id":         cert_id or None,
                    "first_seen":      now,
                })
                continue

            mnc = parsed["mnc"]
            mcc = parsed["mcc"]
            key = (mnc, mcc)
            if key not in enrich_cache:
                enrich_cache[key] = enrich_from_db(conn, mnc, mcc)
            operator, country_name = enrich_cache[key]

            records.append({
                "source":          source,
                "fqdn":            fqdn_lower,
                "service_prefix":  parsed["service_prefix"],
                "zone":            parsed["zone"],
                "in_predefined":   parsed["in_predefined"],
                "is_new_candidate": parsed["is_new_candidate"],
                "mnc":             mnc,
                "mcc":             mcc,
                "operator":        operator,
                "country_name":    country_name,
                "cert_id":         cert_id or None,
                "first_seen":      now,
            })

    return records


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(conn: sqlite3.Connection) -> None:
    total = conn.execute("SELECT COUNT(DISTINCT fqdn) FROM discovered_hosts").fetchone()[0]
    if total == 0:
        print("\n  No passive discovery data in database.")
        print("  Run without --summary-only to collect data first.")
        return

    print(f"\n{'═'*68}")
    print("  Passive Discovery Summary")
    print(f"{'═'*68}")
    print(f"  Total unique FQDNs: {total}")

    # Source breakdown
    print("\n── By Source ─────────────────────────────────────────────────────")
    src_rows = conn.execute(
        "SELECT source, COUNT(DISTINCT fqdn) FROM discovered_hosts "
        "GROUP BY source ORDER BY COUNT(DISTINCT fqdn) DESC"
    ).fetchall()
    for src, cnt in src_rows:
        print(f"  {src:<20} {cnt:>6} unique FQDNs")

    # in_predefined vs new
    pre_cnt = conn.execute(
        "SELECT COUNT(DISTINCT fqdn) FROM discovered_hosts WHERE in_predefined = 1"
    ).fetchone()[0]
    new_cnt = conn.execute(
        "SELECT COUNT(DISTINCT fqdn) FROM discovered_hosts WHERE is_new_candidate = 1"
    ).fetchone()[0]
    unparsed = conn.execute(
        "SELECT COUNT(DISTINCT fqdn) FROM discovered_hosts WHERE service_prefix IS NULL"
    ).fetchone()[0]

    print(f"\n── Classification ────────────────────────────────────────────────")
    print(f"  In predefined SUBDOMAINS list : {pre_cnt:>6}")
    print(f"  New candidates (pub zone)     : {new_cnt:>6}")
    print(f"  Non-canonical / unparsed      : {unparsed:>6}")

    # New candidates detail table
    if new_cnt > 0:
        print(f"\n── NEW CANDIDATES (novel pub-zone prefixes) ─────────────────────")
        header = f"  {'PREFIX':<30}  {'ZONE':<6}  {'SAMPLE MCC':<10}  {'COUNT':>6}"
        print(header)
        print(f"  {'-'*30}  {'-'*6}  {'-'*10}  {'-'*6}")
        cand_rows = conn.execute(
            """
            SELECT service_prefix,
                   zone,
                   MIN(mcc)          AS sample_mcc,
                   COUNT(DISTINCT fqdn) AS cnt
            FROM   discovered_hosts
            WHERE  is_new_candidate = 1
            GROUP  BY service_prefix, zone
            ORDER  BY cnt DESC, service_prefix
            """
        ).fetchall()
        for row in cand_rows:
            print(
                f"  {row['service_prefix']:<30}  {row['zone']:<6}  "
                f"{str(row['sample_mcc']):<10}  {row['cnt']:>6}"
            )

    print(f"{'═'*68}\n")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Passive 3GPP host discovery via Certificate Transparency (crt.sh) "
            "and HackerTarget passive DNS. No packets are sent to 3GPP endpoints."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 3gpppub-passive-discovery.py
  python3 3gpppub-passive-discovery.py --limit 500
  python3 3gpppub-passive-discovery.py --summary-only
  python3 3gpppub-passive-discovery.py --db /data/scan.db --limit 0
        """,
    )
    parser.add_argument(
        "--db",
        default="database.db",
        metavar="FILE",
        help="SQLite database path (default: database.db)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Limit crt.sh results to first N unique FQDNs (0 = unlimited, default: 0)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print summary of existing database data without issuing new HTTP queries",
    )
    args = parser.parse_args()

    conn = init_db(args.db)

    if args.summary_only:
        print_summary(conn)
        conn.close()
        return

    # ── Query sources ─────────────────────────────────────────────────────────
    start = time.time()

    crt_entries = query_crt_sh(limit=args.limit)
    ht_fqdns    = query_hackertarget()

    total_raw = len(crt_entries) + len(ht_fqdns)
    log.info("Raw FQDNs collected: %d (crt.sh=%d, hackertarget=%d)",
             total_raw, len(crt_entries), len(ht_fqdns))

    # ── Build & save records ──────────────────────────────────────────────────
    records  = build_records(conn, crt_entries, ht_fqdns)
    inserted = save_hosts(conn, records)

    elapsed = time.time() - start
    log.info(
        "Done in %.1fs — %d records prepared, %d newly inserted",
        elapsed, len(records), inserted,
    )

    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
