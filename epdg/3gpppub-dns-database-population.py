#!/usr/bin/env python3
"""
3GPP Public Domain DNS Scanner
Discovers and stores DNS records for 3GPP public network services
across all known MCC/MNC operator pairs.

Services checked (pub.3gppnetwork.org zone):

  VoWiFi / ePDG:
    epdg.epc       — ePDG (Wi-Fi Calling gateway, IKEv2/IPsec)
    ss.epdg.epc    — ePDG steering / load-balancing prefix (T-Mobile US)
    sos.epdg.epc   — Emergency ePDG (IKEv2 for SOS calls over Wi-Fi)
    vowifi         — Non-standard VoWiFi alias (AT&T, some US operators)

  5G Non-3GPP Access:
    n3iwf.5gc      — N3IWF (5G untrusted non-3GPP access, replaces ePDG in 5GS)

  IMS / VoLTE:
    ims            — IMS core (VoLTE registration)
    pcscf.ims      — P-CSCF discovery (SIP signaling entry point)
    mmtel.ims      — MMTel supplementary services (call fwd, barring etc.)
    xcap.ims       — XCAP device/service configuration
    ut.ims         — Ut interface for supplementary service config (TS 24.623)

  Emergency:
    sos            — SOS/Emergency services
    sos.ims        — Emergency IMS
    aes            — Authentication/Emergency services (T-Mobile MX, MCC334)

  Other:
    bsf            — Bootstrapping Server Function (5G auth, TS 33.220)
    gan            — GAN/UMA (Generic/Unlicensed Access Network)
    rcs            — Rich Communication Services (GSMA IR.94)
    subs           — Subscription/provisioning (Canadian MNOs, MCC302)
    cota-sdk       — COTA (Carrier Over-The-Air) config endpoint (T-Mobile MX)
"""

import argparse
import json
import logging
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import requests
from dns.resolver import NXDOMAIN, NoAnswer, Timeout

from subdomains import SUBDOMAINS, fqdn_to_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("3gpppub-scan.log"),
    ],
)
log = logging.getLogger(__name__)

PARENT_DOMAIN = "pub.3gppnetwork.org"
MCC_MNC_URL = "https://raw.githubusercontent.com/pbakondy/mcc-mnc-list/master/mcc-mnc-list.json"

SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mnc          INTEGER NOT NULL,
    mcc          INTEGER NOT NULL,
    operator     TEXT    NOT NULL,
    country_name TEXT,
    country_code TEXT,
    last_scanned TIMESTAMP,
    UNIQUE(mnc, mcc)
);

CREATE TABLE IF NOT EXISTS available_fqdns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mnc          INTEGER NOT NULL,
    mcc          INTEGER NOT NULL,
    operator     TEXT    NOT NULL,
    country_name TEXT,
    fqdn         TEXT    NOT NULL,
    record_type  TEXT    NOT NULL DEFAULT 'A',
    service      TEXT,
    resolved_ips TEXT,
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fqdn, record_type)
);

CREATE INDEX IF NOT EXISTS idx_fqdns_mcc     ON available_fqdns(mcc);
CREATE INDEX IF NOT EXISTS idx_fqdns_country ON available_fqdns(country_name);
CREATE INDEX IF NOT EXISTS idx_ops_country   ON operators(country_name);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    # Migrate existing DBs that pre-date the service column
    try:
        conn.execute("ALTER TABLE available_fqdns ADD COLUMN service TEXT")
        conn.commit()
        log.info("Migrated available_fqdns: added service column")
    except sqlite3.OperationalError:
        pass  # Column already present
    conn.commit()
    return conn


def resolve_fqdn(fqdn: str, record_type: str, retries: int = 2) -> list[str]:
    for attempt in range(retries + 1):
        try:
            answers = dns.resolver.resolve(fqdn, record_type)
            return [rdata.address for rdata in answers]
        except (NXDOMAIN, NoAnswer):
            return []
        except Timeout:
            if attempt < retries:
                time.sleep(0.3 * (attempt + 1))
            return []
        except Exception:
            return []
    return []


def check_operator(item: dict, subdomains: list[str], record_types: list[str]) -> dict:
    try:
        mcc = int(item["mcc"])
        mnc = int(item["mnc"])
    except (KeyError, ValueError):
        return {}

    operator     = item.get("operator", "Unknown")
    country_name = item.get("countryName", "Unknown")
    country_code = item.get("countryCode", "")

    found = []
    for subdomain in subdomains:
        fqdn = f"{subdomain}.mnc{mnc:03d}.mcc{mcc:03d}.{PARENT_DOMAIN}"
        for rtype in record_types:
            ips = resolve_fqdn(fqdn, rtype)
            if ips:
                found.append({
                    "fqdn":         fqdn,
                    "record_type":  rtype,
                    "resolved_ips": ",".join(ips),
                })
                log.info("  [+] %s %s -> %s", rtype, fqdn, ", ".join(ips))

    return {
        "mnc": mnc, "mcc": mcc,
        "operator": operator, "country_name": country_name,
        "country_code": country_code,
        "found": found,
    }


def save_result(conn: sqlite3.Connection, result: dict) -> None:
    if not result:
        return
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """
            INSERT INTO operators (mnc, mcc, operator, country_name, country_code, last_scanned)
            VALUES (:mnc, :mcc, :operator, :country_name, :country_code, :now)
            ON CONFLICT(mnc, mcc) DO UPDATE SET
                operator     = excluded.operator,
                country_name = excluded.country_name,
                country_code = excluded.country_code,
                last_scanned = excluded.last_scanned
            """,
            {**result, "now": now},
        )
        for fqdn_entry in result.get("found", []):
            conn.execute(
                """
                INSERT INTO available_fqdns
                    (mnc, mcc, operator, country_name, fqdn, record_type, service, resolved_ips, first_seen, last_seen)
                VALUES
                    (:mnc, :mcc, :operator, :country_name, :fqdn, :record_type, :service, :resolved_ips, :now, :now)
                ON CONFLICT(fqdn, record_type) DO UPDATE SET
                    service      = excluded.service,
                    resolved_ips = excluded.resolved_ips,
                    last_seen    = excluded.last_seen
                """,
                {
                    "mnc":          result["mnc"],
                    "mcc":          result["mcc"],
                    "operator":     result["operator"],
                    "country_name": result["country_name"],
                    "fqdn":         fqdn_entry["fqdn"],
                    "record_type":  fqdn_entry["record_type"],
                    "service":      fqdn_to_service(fqdn_entry["fqdn"]),
                    "resolved_ips": fqdn_entry["resolved_ips"],
                    "now":          now,
                },
            )


def load_mcc_mnc_list(source: str) -> list[dict]:
    if source.startswith("http"):
        log.info("Fetching MCC/MNC list from %s", source)
        response = requests.get(source, timeout=30)
        response.raise_for_status()
        return response.json()
    log.info("Loading MCC/MNC list from %s", source)
    with open(source) as f:
        return json.load(f)


def print_summary(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT country_name,
               COUNT(DISTINCT mcc || '-' || mnc) AS operators,
               COUNT(*) AS total_fqdns
        FROM available_fqdns
        GROUP BY country_name
        ORDER BY total_fqdns DESC
        LIMIT 20
        """
    ).fetchall()
    print("\n--- Top 20 Countries by Discovered Services ---")
    print(f"{'Country':<35} {'Operators':>9} {'FQDNs':>7}")
    print("-" * 55)
    for row in rows:
        print(f"{row['country_name']:<35} {row['operators']:>9} {row['total_fqdns']:>7}")

    # Per-service breakdown — uses stored service column, no CASE WHEN needed
    svc_rows = conn.execute(
        """
        SELECT COALESCE(service, 'other') AS service,
               COUNT(DISTINCT mcc || '-' || mnc) AS operators
        FROM available_fqdns
        GROUP BY service
        ORDER BY operators DESC
        """
    ).fetchall()
    print("\n--- Discovered Services ---")
    for row in svc_rows:
        print(f"  {row[0]:<20} {row[1]:>5} operators")

    totals = conn.execute(
        "SELECT COUNT(*) AS fqdns, COUNT(DISTINCT country_name) AS countries FROM available_fqdns"
    ).fetchone()
    print(f"\nTotal FQDNs found : {totals['fqdns']}")
    print(f"Countries covered : {totals['countries']}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan 3GPP public DNS records for all known MCC/MNC pairs."
    )
    parser.add_argument("--db",      default="database.db")
    parser.add_argument("--source",  default=MCC_MNC_URL)
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--ipv6",    action="store_true")
    parser.add_argument(
        "--subdomains", nargs="+", default=SUBDOMAINS,
        help="Subdomains to probe (default: all known pub.3gppnetwork.org services)",
    )
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()

    conn = init_db(args.db)

    if args.summary_only:
        print_summary(conn)
        conn.close()
        return

    record_types = ["A", "AAAA"] if args.ipv6 else ["A"]
    log.info(
        "Starting scan | workers=%d | record_types=%s | %d subdomains",
        args.workers, record_types, len(args.subdomains),
    )

    mcc_mnc_list = load_mcc_mnc_list(args.source)
    total        = len(mcc_mnc_list)
    log.info("Loaded %d MCC/MNC entries", total)

    completed = found_total = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(check_operator, item, args.subdomains, record_types): item
            for item in mcc_mnc_list
        }
        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                if result:
                    save_result(conn, result)
                    found_this = len(result.get("found", []))
                    found_total += found_this
                    if found_this:
                        log.info(
                            "[%d/%d] %s (%s) -> %d records",
                            completed, total,
                            result["operator"], result["country_name"], found_this,
                        )
                    elif completed % 100 == 0:
                        elapsed = time.time() - start_time
                        rate = completed / elapsed
                        eta  = (total - completed) / rate if rate > 0 else 0
                        log.info(
                            "[%d/%d] %.1f ops/s | ETA %.0fs | found %d FQDNs so far",
                            completed, total, rate, eta, found_total,
                        )
            except Exception as exc:
                log.warning("Worker error: %s", exc)

    elapsed = time.time() - start_time
    log.info(
        "Scan complete in %.1fs | %d operators | %d FQDNs found",
        elapsed, completed, found_total,
    )
    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
