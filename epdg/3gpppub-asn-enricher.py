#!/usr/bin/env python3
"""
Feature 1: ASN / BGP Enricher
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Resolves every IP in the database to its ASN, organisation, and cloud provider
using the Team Cymru bulk whois service (free, no API key, no rate-limit).

Adds columns to available_fqdns:
  asn              e.g. "AS15169"
  asn_org          e.g. "GOOGLE, US"
  hosting_provider e.g. "Google Cloud"
  ip_country       e.g. "US"

Also outputs a cloud-provider breakdown so you can see which fraction of
mobile-operator infrastructure runs on AWS, Azure, GCP vs on-premises.

Usage:
  python3 3gpppub-asn-enricher.py
  python3 3gpppub-asn-enricher.py --db database.db --summary-only
"""

import argparse
import logging
import re
import socket
import sqlite3
import sys
from collections import Counter
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ── Cloud / hosting provider fingerprints ────────────────────────────────────
# Matched against the AS-name returned by Cymru (case-insensitive substring)

PROVIDER_FINGERPRINTS = [
    ("Amazon AWS",       ["AMAZON", "AWS", "EC2"]),
    ("Google Cloud",     ["GOOGLE", "GOOG-"]),
    ("Microsoft Azure",  ["MICROSOFT", "MSFT"]),
    ("Alibaba Cloud",    ["ALIBABA", "ALICLOUD"]),
    ("Cloudflare",       ["CLOUDFLARE"]),
    ("Akamai",           ["AKAMAI"]),
    ("OVH",              ["OVH"]),
    ("Hetzner",          ["HETZNER"]),
    ("DigitalOcean",     ["DIGITALOCEAN", "DIGIT-"]),
    ("Oracle Cloud",     ["ORACLE-"]),
    ("Lumen/CenturyLink",["LUMEN", "CENTURYLINK", "LEVEL3", "LVLT-"]),
    ("Tata Comm/IZO",    ["TATA", "TATAINDICOM"]),
    ("BICS",             ["BICS"]),
    ("Syniverse",        ["SYNIVERSE"]),
    ("IPX/GRX",          ["TELIGENT", "NTT", "GTLD", "ROAMEX"]),
]

def fingerprint_provider(asn_org: str) -> str:
    upper = asn_org.upper()
    for label, keywords in PROVIDER_FINGERPRINTS:
        if any(kw in upper for kw in keywords):
            return label
    return "On-premises / Other"


# ── Team Cymru bulk whois ─────────────────────────────────────────────────────

def cymru_bulk_lookup(ips: list[str]) -> dict[str, dict]:
    """
    Query Team Cymru whois (whois.cymru.com:43) for a list of IPs.
    Returns dict: ip -> {asn, prefix, country, registry, allocated, asn_org}
    """
    if not ips:
        return {}

    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    raw = b""
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=30) as sock:
            sock.sendall(query.encode())
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                raw += chunk
    except Exception as exc:
        log.error("Cymru whois failed: %s", exc)
        return {}

    results = {}
    # Header line starts with "AS" — skip it
    for line in raw.decode(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("AS ") or line.startswith("Bulk"):
            continue
        # Format: AS | IP | Prefix | CC | Registry | Allocated | AS Name
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn_raw, ip, prefix, cc, registry, allocated, asn_name = parts[:7]
        asn = asn_raw.strip()
        if not asn.lstrip("0123456789"):
            asn = f"AS{asn}"
        results[ip] = {
            "asn":       asn,
            "prefix":    prefix,
            "ip_country": cc,
            "registry":  registry,
            "allocated": allocated,
            "asn_org":   asn_name,
            "hosting_provider": fingerprint_provider(asn_name),
        }
    return results


# ── DB helpers ────────────────────────────────────────────────────────────────

ENRICH_COLUMNS = {
    "asn":              "TEXT",
    "asn_org":          "TEXT",
    "hosting_provider": "TEXT",
    "ip_country":       "TEXT",
    "bgp_prefix":       "TEXT",
}

def ensure_columns(conn: sqlite3.Connection) -> None:
    existing = {row[1] for row in conn.execute("PRAGMA table_info(available_fqdns)")}
    for col, coltype in ENRICH_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE available_fqdns ADD COLUMN {col} {coltype}")
    conn.commit()


def get_unenriched_ips(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """Return (rowid, ip) pairs that still need enrichment."""
    rows = conn.execute(
        """
        SELECT id, resolved_ips
        FROM available_fqdns
        WHERE resolved_ips IS NOT NULL
          AND resolved_ips != ''
          AND (asn IS NULL OR asn = '')
        """
    ).fetchall()
    pairs = []
    for row_id, ip_csv in rows:
        for ip in ip_csv.split(","):
            ip = ip.strip()
            if ip:
                pairs.append((row_id, ip))
    return pairs


def apply_enrichment(conn: sqlite3.Connection, row_id: int, info: dict) -> None:
    conn.execute(
        """
        UPDATE available_fqdns
        SET asn = :asn,
            asn_org = :asn_org,
            hosting_provider = :hosting_provider,
            ip_country = :ip_country,
            bgp_prefix = :prefix
        WHERE id = :id
        """,
        {**info, "id": row_id},
    )


def print_summary(conn: sqlite3.Connection) -> None:
    print("\n─── Cloud / Hosting Provider Distribution ───────────────────────────")
    rows = conn.execute(
        """
        SELECT hosting_provider, COUNT(*) AS cnt
        FROM available_fqdns
        WHERE hosting_provider IS NOT NULL
        GROUP BY hosting_provider
        ORDER BY cnt DESC
        """
    ).fetchall()
    total = sum(r[1] for r in rows) or 1
    for provider, cnt in rows:
        bar = "█" * int(30 * cnt / total)
        print(f"  {provider:<25} {cnt:>5}  {bar}")

    print("\n─── Top ASNs ─────────────────────────────────────────────────────────")
    asn_rows = conn.execute(
        """
        SELECT asn, asn_org, COUNT(*) AS cnt
        FROM available_fqdns
        WHERE asn IS NOT NULL
        GROUP BY asn
        ORDER BY cnt DESC
        LIMIT 15
        """
    ).fetchall()
    for asn, org, cnt in asn_rows:
        print(f"  {asn:<10} {cnt:>5}  {org}")

    print("\n─── Operators on Cloud vs On-premises ───────────────────────────────")
    cloud_ops = conn.execute(
        """
        SELECT hosting_provider,
               COUNT(DISTINCT mcc || '-' || mnc) AS operators
        FROM available_fqdns
        WHERE hosting_provider IS NOT NULL
        GROUP BY hosting_provider
        ORDER BY operators DESC
        """
    ).fetchall()
    for provider, ops in cloud_ops:
        print(f"  {provider:<25} {ops:>4} operators")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Enrich DB IPs with ASN / hosting provider info.")
    parser.add_argument("--db", default="database.db")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="IPs per Cymru query (default: 500)")
    parser.add_argument("--summary-only", action="store_true",
                        help="Print existing enrichment summary and exit")
    args = parser.parse_args()

    if not Path(args.db).exists():
        log.error("Database %s not found. Run the population script first.", args.db)
        sys.exit(1)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    ensure_columns(conn)

    if args.summary_only:
        print_summary(conn)
        conn.close()
        return

    pairs = get_unenriched_ips(conn)
    if not pairs:
        log.info("All IPs already enriched.")
        print_summary(conn)
        conn.close()
        return

    log.info("%d IPs to enrich in batches of %d", len(pairs), args.batch_size)

    # Deduplicate IPs while remembering which row IDs need each
    ip_to_rows: dict[str, list[int]] = {}
    for row_id, ip in pairs:
        ip_to_rows.setdefault(ip, []).append(row_id)

    unique_ips = list(ip_to_rows.keys())
    enriched = 0

    for batch_start in range(0, len(unique_ips), args.batch_size):
        batch = unique_ips[batch_start : batch_start + args.batch_size]
        log.info("Querying Cymru: IPs %d–%d", batch_start + 1, batch_start + len(batch))
        results = cymru_bulk_lookup(batch)

        for ip, info in results.items():
            for row_id in ip_to_rows.get(ip, []):
                apply_enrichment(conn, row_id, info)
                enriched += 1

        conn.commit()
        log.info("  → %d enrichments committed", enriched)

    log.info("Done. %d rows enriched.", enriched)
    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
