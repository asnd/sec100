#!/usr/bin/env python3
"""
Feature 4: NAPTR / SRV Record Probing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Goes beyond A/AAAA records to discover the SIP/IMS topology published by
each operator in their 3GPP public DNS zone.

NAPTR (Naming Authority Pointer) records reveal:
  • Transport protocol preference: UDP / TCP / TLS
  • SIP service types: SIP, SIPS, E2U+sip
  • Next-hop domain for SRV resolution

SRV (Service) records reveal:
  • P-CSCF / S-CSCF / I-CSCF hostnames and ports
  • Priority and weight for load-balancing
  • IKEv2 (ePDG) endpoint details

For each operator that already has an IMS or ePDG A record in the DB,
this script queries NAPTR and then follows with SRV for the returned targets.

Results are stored in `naptr_records` and `srv_records` tables.

Usage:
  python3 3gpppub-naptr-discovery.py
  python3 3gpppub-naptr-discovery.py --workers 10 --summary-only
"""

import argparse
import logging
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
from dns.resolver import NXDOMAIN, NoAnswer, Timeout

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("naptr-scan.log")],
)
log = logging.getLogger(__name__)

SCHEMA_NAPTR = """
CREATE TABLE IF NOT EXISTS naptr_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    base_fqdn    TEXT NOT NULL,
    order_val    INTEGER,
    preference   INTEGER,
    flags        TEXT,
    service      TEXT,
    regexp       TEXT,
    replacement  TEXT,
    operator     TEXT,
    country_name TEXT,
    mnc          INTEGER,
    mcc          INTEGER,
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS srv_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    query_name   TEXT NOT NULL,
    priority     INTEGER,
    weight       INTEGER,
    port         INTEGER,
    target       TEXT,
    operator     TEXT,
    country_name TEXT,
    mnc          INTEGER,
    mcc          INTEGER,
    source_fqdn  TEXT,
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_naptr_base    ON naptr_records(base_fqdn);
CREATE INDEX IF NOT EXISTS idx_naptr_country ON naptr_records(country_name);
CREATE INDEX IF NOT EXISTS idx_srv_query     ON srv_records(query_name);
"""

# SRV names to probe for IMS (RFC 3263 / 3GPP TS 24.229)
IMS_SRV_TEMPLATES = [
    "_sip._udp.{fqdn}",
    "_sip._tcp.{fqdn}",
    "_sips._tcp.{fqdn}",
    "_sip._tls.{fqdn}",
]

# SRV names to probe for ePDG (3GPP TS 24.302)
EPDG_SRV_TEMPLATES = [
    "_eap._udp.{fqdn}",
    "_ikev2._udp.{fqdn}",
]


def init_db(db_path: str) -> sqlite3.Connection:
    if not Path(db_path).exists():
        log.error("Database %s not found. Run population script first.", db_path)
        sys.exit(1)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_NAPTR)
    conn.commit()
    return conn


def query_naptr(fqdn: str) -> list[dict]:
    try:
        answers = dns.resolver.resolve(fqdn, "NAPTR")
        return [
            {
                "order_val":   r.order,
                "preference":  r.preference,
                "flags":       r.flags.decode(errors="replace") if isinstance(r.flags, bytes) else str(r.flags),
                "service":     r.service.decode(errors="replace") if isinstance(r.service, bytes) else str(r.service),
                "regexp":      r.regexp.decode(errors="replace") if isinstance(r.regexp, bytes) else str(r.regexp),
                "replacement": str(r.replacement).rstrip("."),
            }
            for r in answers
        ]
    except (NXDOMAIN, NoAnswer, Timeout):
        return []
    except Exception:
        return []


def query_srv(name: str) -> list[dict]:
    try:
        answers = dns.resolver.resolve(name, "SRV")
        return [
            {
                "priority": r.priority,
                "weight":   r.weight,
                "port":     r.port,
                "target":   str(r.target).rstrip("."),
            }
            for r in answers
        ]
    except (NXDOMAIN, NoAnswer, Timeout):
        return []
    except Exception:
        return []


def probe_operator_naptr(row: dict) -> dict:
    fqdn        = row["fqdn"]
    operator    = row["operator"]
    country     = row["country_name"]
    mnc         = row["mnc"]
    mcc         = row["mcc"]
    service     = row["service"]

    natptrs = query_naptr(fqdn)
    srvs    = []

    # Query predefined SRV names based on service type
    templates = IMS_SRV_TEMPLATES if "ims" in service else EPDG_SRV_TEMPLATES
    for tmpl in templates:
        srv_name = tmpl.format(fqdn=fqdn)
        entries  = query_srv(srv_name)
        if entries:
            for e in entries:
                e["query_name"] = srv_name
            srvs.extend(entries)
            log.info("  [SRV] %s → %d records", srv_name, len(entries))

    # Also follow NAPTR replacements with SRV if replacement domain looks like a SRV target
    for naptr in natptrs:
        rep = naptr["replacement"]
        if rep and rep != ".":
            for tmpl in IMS_SRV_TEMPLATES:
                srv_name = tmpl.format(fqdn=rep)
                entries  = query_srv(srv_name)
                if entries:
                    for e in entries:
                        e["query_name"] = srv_name
                    srvs.extend(entries)

    if natptrs:
        log.info("  [NAPTR] %s → %d records | %s (%s)",
                 fqdn, len(natptrs), operator, country)

    return {
        "fqdn": fqdn, "mnc": mnc, "mcc": mcc,
        "operator": operator, "country_name": country,
        "naptr": natptrs, "srv": srvs,
    }


def save_naptr_result(conn: sqlite3.Connection, result: dict) -> None:
    now = datetime.now(timezone.utc).isoformat()
    base = {
        "base_fqdn":    result["fqdn"],
        "operator":     result["operator"],
        "country_name": result["country_name"],
        "mnc":          result["mnc"],
        "mcc":          result["mcc"],
    }
    with conn:
        for rec in result.get("naptr", []):
            conn.execute(
                """
                INSERT OR IGNORE INTO naptr_records
                    (base_fqdn, order_val, preference, flags, service, regexp,
                     replacement, operator, country_name, mnc, mcc, first_seen)
                VALUES (:base_fqdn, :order_val, :preference, :flags, :service, :regexp,
                        :replacement, :operator, :country_name, :mnc, :mcc, :first_seen)
                """,
                {**base, **rec, "first_seen": now},
            )
        for rec in result.get("srv", []):
            conn.execute(
                """
                INSERT OR IGNORE INTO srv_records
                    (query_name, priority, weight, port, target,
                     operator, country_name, mnc, mcc, source_fqdn, first_seen)
                VALUES (:query_name, :priority, :weight, :port, :target,
                        :operator, :country_name, :mnc, :mcc, :source_fqdn, :first_seen)
                """,
                {
                    **base,
                    "query_name":  rec["query_name"],
                    "priority":    rec["priority"],
                    "weight":      rec["weight"],
                    "port":        rec["port"],
                    "target":      rec["target"],
                    "source_fqdn": result["fqdn"],
                    "first_seen":  now,
                },
            )


def print_summary(conn: sqlite3.Connection) -> None:
    n_naptr = conn.execute("SELECT COUNT(*) FROM naptr_records").fetchone()[0]
    n_srv   = conn.execute("SELECT COUNT(*) FROM srv_records").fetchone()[0]
    print(f"\n{'═'*65}")
    print("  NAPTR/SRV Discovery Summary")
    print(f"{'═'*65}")
    print(f"  NAPTR records : {n_naptr}")
    print(f"  SRV records   : {n_srv}")

    if n_naptr == 0:
        return

    print("\n── Transport Preferences (from NAPTR service field) ─────────────")
    svc_rows = conn.execute(
        "SELECT service, COUNT(*) AS cnt FROM naptr_records GROUP BY service ORDER BY cnt DESC"
    ).fetchall()
    for row in svc_rows:
        print(f"  {row[0] or '(empty)':<30} {row[1]:>5} records")

    print("\n── SRV Port Distribution (IMS / ePDG) ───────────────────────────")
    port_rows = conn.execute(
        "SELECT port, COUNT(*) AS cnt FROM srv_records GROUP BY port ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    port_names = {5060: "SIP/UDP", 5061: "SIP/TLS", 5062: "SIP/TCP",
                  4500: "IKEv2/NAT-T", 500: "IKEv2"}
    for row in port_rows:
        pname = port_names.get(row[0], "")
        print(f"  port {row[0]:>5}  ({pname:<12})  {row[1]:>5} records")

    print("\n── Countries with NAPTR ─────────────────────────────────────────")
    ctry_rows = conn.execute(
        """
        SELECT country_name, COUNT(DISTINCT mcc || '-' || mnc) AS ops, COUNT(*) AS recs
        FROM naptr_records
        GROUP BY country_name ORDER BY recs DESC LIMIT 10
        """
    ).fetchall()
    for row in ctry_rows:
        print(f"  {row[0]:<35} {row[1]:>4} operators  {row[2]:>5} records")


def main():
    parser = argparse.ArgumentParser(
        description="Probe NAPTR and SRV records for discovered 3GPP IMS/ePDG domains."
    )
    parser.add_argument("--db",      default="database.db")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--summary-only", action="store_true")
    parser.add_argument(
        "--services", nargs="+",
        default=["ims", "epdg.epc", "pcscf.ims", "xcap.ims", "bsf", "n3iwf.5gc"],
        help="Services to probe for NAPTR/SRV",
    )
    args = parser.parse_args()

    conn = init_db(args.db)

    if args.summary_only:
        print_summary(conn)
        conn.close()
        return

    # Get candidate FQDNs from existing A-record discoveries
    service_filter = " OR ".join(f"fqdn LIKE '{s}.%'" for s in args.services)
    rows = conn.execute(
        f"""
        SELECT DISTINCT fqdn, operator, country_name, mnc, mcc,
               CASE
                 WHEN fqdn LIKE 'epdg.epc%' THEN 'epdg.epc'
                 WHEN fqdn LIKE 'xcap.ims%' THEN 'xcap.ims'
                 WHEN fqdn LIKE 'ims%'      THEN 'ims'
                 WHEN fqdn LIKE 'bsf%'      THEN 'bsf'
                 ELSE 'other'
               END AS service
        FROM available_fqdns
        WHERE record_type = 'A' AND ({service_filter})
        ORDER BY country_name
        """
    ).fetchall()

    candidates = [dict(r) for r in rows]
    log.info("Probing NAPTR/SRV for %d FQDNs with %d workers", len(candidates), args.workers)

    naptr_found = srv_found = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(probe_operator_naptr, row): row for row in candidates}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result()
                n = len(result.get("naptr", []))
                s = len(result.get("srv",   []))
                if n or s:
                    save_naptr_result(conn, result)
                    naptr_found += n
                    srv_found   += s
                if i % 200 == 0:
                    log.info("[%d/%d] NAPTR found: %d, SRV found: %d",
                             i, len(candidates), naptr_found, srv_found)
            except Exception as exc:
                log.debug("Worker error: %s", exc)

    log.info("Done — %d NAPTR records, %d SRV records", naptr_found, srv_found)
    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
