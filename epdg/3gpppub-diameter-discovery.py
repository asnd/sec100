#!/usr/bin/env python3
"""
Feature: Diameter / GSMA Roaming Realm Enumeration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Enumerates 3GPP Diameter signalling realms via DNS NAPTR and SRV records.

DIAMETER DNS CONTEXT
─────────────────────
3GPP Diameter realm DNS is defined in RFC 6408 (S-NAPTR for Diameter) and
3GPP TS 29.272/29.234.  The canonical realm pattern for EPC is:

  epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org

Applications (interfaces) are identified by NAPTR service codes:

  aaa+ap1   — NASREQ         (RFC 4005)
  aaa+ap6   — Diameter Accounting
  aaa+ap16  — Cx             (3GPP TS 29.228, HSS / I-CSCF)
  aaa+ap23  — S6a            (3GPP TS 29.272, HSS / MME)  ← most common
  aaa+ap24  — S6b            (3GPP TS 29.273, PDN-GW / AAA)
  aaa+ap25  — SWm            (3GPP TS 29.273, ePDG / AAA)
  aaa+ap26  — SWx            (3GPP TS 29.273, AAA-Server / HSS)

SECURITY CONTEXT (GSMA IR.88 / PRD IR.77)
───────────────────────────────────────────
Diameter EPC realms and their SRV targets are intended to live in
GRX/IPX private DNS (GSMA IR.34, IR.67) and MUST NOT be reachable from
the public internet.  Finding any of the below via public DNS is itself
a GSMA IR.88 security finding:

  • A record for epc.mnc<X>.mcc<Y>.3gppnetwork.org  → realm reachable
  • NAPTR for the same domain                         → Diameter topology exposed
  • SRV _diameter._tcp/<_sctp>.<replacement>          → peer hostname / port exposed

GRX/IPX ACCESS
───────────────
If you have GRX or IPX connectivity (operator lab, academic peering):
  --dns-server <GRX_RESOLVER_IP>   → full enumeration
  --dns-server 185.89.218.1        → example BICS GRX (illustrative; verify)

Usage:
  # Public DNS — discovers operators that (mis)publish Diameter realms publicly
  python3 3gpppub-diameter-discovery.py

  # Via GRX resolver (full enumeration)
  python3 3gpppub-diameter-discovery.py --dns-server <GRX_IP>

  # Load operators from existing database instead of fetching list
  python3 3gpppub-diameter-discovery.py --db database.db

  # Summary of what was found
  python3 3gpppub-diameter-discovery.py --db database.db --summary-only

  # Limit to first N operators (testing)
  python3 3gpppub-diameter-discovery.py --limit 100
"""

from __future__ import annotations

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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("diameter-scan.log"),
    ],
)
log = logging.getLogger(__name__)

MCC_MNC_URL = (
    "https://raw.githubusercontent.com/pbakondy/mcc-mnc-list/master/mcc-mnc-list.json"
)

# ── Diameter realm templates (3GPP TS 23.003) ─────────────────────────────────
REALM_TEMPLATES = [
    "epc.mnc{mnc:03d}.mcc{mcc:03d}.3gppnetwork.org",
    "ims.mnc{mnc:03d}.mcc{mcc:03d}.3gppnetwork.org",
    "mnc{mnc:03d}.mcc{mcc:03d}.3gppnetwork.org",
]

# ── Diameter application service codes (RFC 6408 + 3GPP TS 29.272) ───────────
DIAMETER_SERVICES = {
    "aaa+ap1":  "NASREQ",
    "aaa+ap6":  "Diameter-Accounting",
    "aaa+ap16": "Cx(HSS/I-CSCF)",
    "aaa+ap23": "S6a(HSS/MME)",
    "aaa+ap24": "S6b(PDN-GW/AAA)",
    "aaa+ap25": "SWm(ePDG/AAA)",
    "aaa+ap26": "SWx(AAA/HSS)",
}

# Interface priority for primary interface detection (most specific / security-relevant first)
INTERFACE_PRIORITY = [
    "aaa+ap23",  # S6a — HSS/MME, most common EPC Diameter
    "aaa+ap16",  # Cx  — IMS HSS
    "aaa+ap25",  # SWm — ePDG, directly related to WiFi calling
    "aaa+ap26",  # SWx — AAA/HSS
    "aaa+ap24",  # S6b — PDN-GW
    "aaa+ap6",   # Accounting
    "aaa+ap1",   # NASREQ
]

# ── Database schema ────────────────────────────────────────────────────────────
SCHEMA_DIAMETER = """
CREATE TABLE IF NOT EXISTS diameter_realms (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mnc             INTEGER NOT NULL,
    mcc             INTEGER NOT NULL,
    operator        TEXT,
    country_name    TEXT,
    realm           TEXT    NOT NULL,
    naptr_found     INTEGER NOT NULL DEFAULT 0,
    naptr_services  TEXT,
    srv_hosts       TEXT,
    interface       TEXT,
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(realm)
);

CREATE TABLE IF NOT EXISTS diameter_peers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    realm           TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    transport       TEXT    NOT NULL,
    resolved_ips    TEXT,
    operator        TEXT,
    country_name    TEXT,
    mnc             INTEGER,
    mcc             INTEGER,
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host, port)
);

CREATE INDEX IF NOT EXISTS idx_diameter_realm_country  ON diameter_realms(country_name);
CREATE INDEX IF NOT EXISTS idx_diameter_realm_iface    ON diameter_realms(interface);
CREATE INDEX IF NOT EXISTS idx_diameter_realm_mcc      ON diameter_realms(mcc);
CREATE INDEX IF NOT EXISTS idx_diameter_peers_realm    ON diameter_peers(realm);
"""


# ── DNS helpers ────────────────────────────────────────────────────────────────

def make_resolver(dns_server: str | None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout  = 4
    r.lifetime = 8
    if dns_server:
        r.nameservers = [dns_server]
        log.info("Using custom DNS resolver: %s", dns_server)
    return r


def resolve_a(fqdn: str, resolver: dns.resolver.Resolver) -> list[str]:
    """Resolve A records; empty list on any failure."""
    try:
        answers = resolver.resolve(fqdn, "A")
        return [r.address for r in answers]
    except (NXDOMAIN, NoAnswer, Timeout):
        return []
    except Exception:
        return []


def resolve_naptr(realm: str, resolver: dns.resolver.Resolver) -> list[dict]:
    """Resolve NAPTR records for a Diameter realm."""
    try:
        answers = resolver.resolve(realm, "NAPTR")
        return [
            {
                "order":       r.order,
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


def resolve_srv(name: str, resolver: dns.resolver.Resolver) -> list[dict]:
    """Resolve SRV records."""
    try:
        answers = resolver.resolve(name, "SRV")
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


# ── Interface detection ────────────────────────────────────────────────────────

def detect_interface(matched_services: list[str]) -> str:
    """Return primary Diameter interface name from matched NAPTR service codes."""
    for code in INTERFACE_PRIORITY:
        if code in matched_services:
            return DIAMETER_SERVICES[code]
    if matched_services:
        return DIAMETER_SERVICES.get(matched_services[0], matched_services[0])
    return ""


# ── Per-operator probe ─────────────────────────────────────────────────────────

def probe_operator(item: dict, resolver: dns.resolver.Resolver) -> dict:
    """
    Probe all Diameter realm patterns for one MCC-MNC entry.

    Returns a dict with keys:
      mnc, mcc, operator, country_name,
      realms: list of realm-result dicts
    """
    try:
        mcc = int(item["mcc"])
        mnc = int(item["mnc"])
    except (KeyError, ValueError):
        return {}

    operator     = item.get("operator") or item.get("operatorName", "Unknown")
    country_name = item.get("countryName") or item.get("country_name", "Unknown")

    realm_results = []

    for tmpl in REALM_TEMPLATES:
        realm = tmpl.format(mnc=mnc, mcc=mcc)

        # Step 1: A record — presence alone is a finding
        a_ips = resolve_a(realm, resolver)

        # Step 2: NAPTR
        naptr_records = resolve_naptr(realm, resolver)

        if not a_ips and not naptr_records:
            continue

        # Identify which Diameter application codes are advertised
        matched_services = []
        for rec in naptr_records:
            svc = rec["service"].lower().strip()
            for code in DIAMETER_SERVICES:
                if code in svc:
                    matched_services.append(code)

        naptr_services_str = ",".join(sorted(set(matched_services))) if matched_services else ""
        interface          = detect_interface(matched_services)

        # Step 3: Follow NAPTR replacements with SRV
        replacements = set()
        for rec in naptr_records:
            rep = rec["replacement"]
            if rep and rep not in (".", ""):
                replacements.add(rep)

        peers = []
        for rep in replacements:
            for transport in ("tcp", "sctp"):
                srv_name = f"_diameter._{transport}.{rep}"
                srv_entries = resolve_srv(srv_name, resolver)
                for entry in srv_entries:
                    host = entry["target"]
                    port = entry["port"]
                    ips  = resolve_a(host, resolver)
                    peers.append({
                        "realm":       realm,
                        "host":        host,
                        "port":        port,
                        "transport":   transport.upper(),
                        "resolved_ips": ",".join(ips),
                        "operator":    operator,
                        "country_name": country_name,
                        "mnc":         mnc,
                        "mcc":         mcc,
                    })
                    log.info(
                        "  [PEER] %s:%d/%s → %s | %s (%s)",
                        host, port, transport.upper(),
                        ",".join(ips) or "unresolved",
                        operator, country_name,
                    )

        srv_hosts_str = ",".join(
            f"{p['host']}:{p['port']}/{p['transport']}" for p in peers
        )

        log.info(
            "  [REALM] %s | NAPTR=%d A=%s iface=%s | %s (%s)",
            realm,
            len(naptr_records),
            bool(a_ips),
            interface or "none",
            operator, country_name,
        )

        realm_results.append({
            "realm":           realm,
            "naptr_found":     1 if naptr_records else 0,
            "naptr_services":  naptr_services_str,
            "srv_hosts":       srv_hosts_str,
            "interface":       interface,
            "peers":           peers,
        })

    return {
        "mnc":          mnc,
        "mcc":          mcc,
        "operator":     operator,
        "country_name": country_name,
        "realms":       realm_results,
    }


# ── Database ───────────────────────────────────────────────────────────────────

def init_db(db_path: str, require_exists: bool = False) -> sqlite3.Connection:
    if require_exists and not Path(db_path).exists():
        log.error("Database %s not found.", db_path)
        sys.exit(1)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_DIAMETER)
    conn.commit()
    return conn


def save_result(conn: sqlite3.Connection, result: dict) -> None:
    if not result or not result.get("realms"):
        return
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        for r in result["realms"]:
            conn.execute(
                """
                INSERT INTO diameter_realms
                    (mnc, mcc, operator, country_name, realm,
                     naptr_found, naptr_services, srv_hosts, interface, first_seen)
                VALUES
                    (:mnc, :mcc, :operator, :country_name, :realm,
                     :naptr_found, :naptr_services, :srv_hosts, :interface, :first_seen)
                ON CONFLICT(realm) DO UPDATE SET
                    naptr_found    = MAX(naptr_found,    excluded.naptr_found),
                    naptr_services = COALESCE(NULLIF(excluded.naptr_services,''), naptr_services),
                    srv_hosts      = COALESCE(NULLIF(excluded.srv_hosts,''), srv_hosts),
                    interface      = COALESCE(NULLIF(excluded.interface,''), interface)
                """,
                {
                    "mnc":           result["mnc"],
                    "mcc":           result["mcc"],
                    "operator":      result["operator"],
                    "country_name":  result["country_name"],
                    "realm":         r["realm"],
                    "naptr_found":   r["naptr_found"],
                    "naptr_services": r["naptr_services"],
                    "srv_hosts":     r["srv_hosts"],
                    "interface":     r["interface"],
                    "first_seen":    now,
                },
            )
            for peer in r.get("peers", []):
                conn.execute(
                    """
                    INSERT OR IGNORE INTO diameter_peers
                        (realm, host, port, transport, resolved_ips,
                         operator, country_name, mnc, mcc, first_seen)
                    VALUES
                        (:realm, :host, :port, :transport, :resolved_ips,
                         :operator, :country_name, :mnc, :mcc, :first_seen)
                    """,
                    {**peer, "first_seen": now},
                )


# ── Operator loading ───────────────────────────────────────────────────────────

def load_operators_from_url(source: str) -> list[dict]:
    """Fetch MCC-MNC list from URL or local JSON file."""
    if source.startswith("http"):
        log.info("Fetching operator list from %s", source)
        resp = requests.get(source, timeout=30)
        resp.raise_for_status()
        return resp.json()
    log.info("Loading operator list from file: %s", source)
    with open(source) as f:
        return json.load(f)


def load_operators_from_db(conn: sqlite3.Connection) -> list[dict]:
    """Load operators from the existing `operators` table in the database."""
    rows = conn.execute(
        "SELECT mnc, mcc, operator, country_name FROM operators"
    ).fetchall()
    return [dict(r) for r in rows]


# ── Summary ────────────────────────────────────────────────────────────────────

def print_summary(conn: sqlite3.Connection) -> None:
    n_realms = conn.execute(
        "SELECT COUNT(*) FROM diameter_realms"
    ).fetchone()[0]
    n_naptr  = conn.execute(
        "SELECT COUNT(*) FROM diameter_realms WHERE naptr_found = 1"
    ).fetchone()[0]
    n_peers  = conn.execute(
        "SELECT COUNT(*) FROM diameter_peers"
    ).fetchone()[0]

    print(f"\n{'═'*68}")
    print("  Diameter / GSMA Roaming Realm Enumeration Summary")
    print(f"{'═'*68}")
    print(f"  Realms found (A or NAPTR) : {n_realms}")
    print(f"  Realms with NAPTR         : {n_naptr}")
    print(f"  Diameter peers discovered : {n_peers}")

    if n_realms == 0:
        print("\n  NOTE: No Diameter realms resolved from public DNS.")
        print("        This is expected — EPC DNS lives in GRX/IPX by design.")
        print("        Use --dns-server <GRX_RESOLVER_IP> for full enumeration.")
        return

    print("\n── By Realm Type ────────────────────────────────────────────────")
    realm_type_rows = conn.execute(
        """
        SELECT
            CASE
                WHEN realm LIKE 'epc.%'  THEN 'epc (EPC/LTE)'
                WHEN realm LIKE 'ims.%'  THEN 'ims (IMS)'
                ELSE                          'base (mnc.mcc)'
            END AS realm_type,
            COUNT(*) AS cnt
        FROM diameter_realms
        GROUP BY realm_type
        ORDER BY cnt DESC
        """
    ).fetchall()
    for row in realm_type_rows:
        print(f"  {row[0]:<30} {row[1]:>5} realms")

    print("\n── By Diameter Interface ────────────────────────────────────────")
    iface_rows = conn.execute(
        """
        SELECT interface, COUNT(*) AS cnt
        FROM diameter_realms
        WHERE interface != ''
        GROUP BY interface
        ORDER BY cnt DESC
        """
    ).fetchall()
    if iface_rows:
        for row in iface_rows:
            print(f"  {row[0]:<30} {row[1]:>5} realms")
    else:
        print("  (no NAPTR service codes detected)")

    print("\n── Top Countries ────────────────────────────────────────────────")
    ctry_rows = conn.execute(
        """
        SELECT country_name,
               COUNT(DISTINCT mcc || '-' || mnc) AS operators,
               COUNT(*) AS realms,
               GROUP_CONCAT(DISTINCT interface) AS interfaces
        FROM diameter_realms
        GROUP BY country_name
        ORDER BY operators DESC
        LIMIT 15
        """
    ).fetchall()
    for row in ctry_rows:
        ifaces = row["interfaces"] or "-"
        print(
            f"  {row['country_name']:<35}"
            f" {row['operators']:>4} operators"
            f" {row['realms']:>5} realms"
            f"  [{ifaces}]"
        )

    if n_peers > 0:
        print("\n── Diameter Peers (host:port/transport) ─────────────────────────")
        peer_rows = conn.execute(
            """
            SELECT realm, host, port, transport, resolved_ips, operator, country_name
            FROM diameter_peers
            ORDER BY country_name, realm
            LIMIT 50
            """
        ).fetchall()
        for row in peer_rows:
            ips = row["resolved_ips"] or "unresolved"
            print(
                f"  {row['country_name']:<20} {row['operator']:<30}"
                f" {row['host']}:{row['port']}/{row['transport']}"
                f" → {ips}"
            )

    print(f"\n{'─'*68}")
    print("  *** SECURITY NOTE (GSMA IR.88 / PRD IR.77) ***")
    print("  Diameter EPC realms MUST reside in GRX/IPX private DNS.")
    print("  Any realm resolvable from public internet is an IR.88 finding.")
    print("  Exposed Diameter NAPTR/SRV reveals roaming topology + peer IPs,")
    print("  enabling targeted SS7/Diameter attacks (e.g. subscriber tracking,")
    print("  location disclosure, authentication-vector interception).")
    print(f"{'─'*68}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate 3GPP Diameter signalling realms via DNS NAPTR/SRV. "
            "Finding EPC DNS reachable from public internet is a GSMA IR.88 finding."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DNS Zone Notes:
  Public DNS  → EPC/Diameter realms should NOT appear here (GSMA IR.88).
                Any positive result is a misconfiguration / security finding.
  GRX/IPX DNS → Full enumeration. Use --dns-server <GRX_RESOLVER_IP> and
                ensure you have GRX/IPX connectivity before scanning.

Operator source (pick one):
  --db database.db          load operators from existing DB (operators table)
  --source <URL or file>    fetch/load mcc-mnc-list JSON (default: GitHub)
        """,
    )
    parser.add_argument(
        "--db",
        default="database.db",
        help="Path to SQLite database (default: database.db)",
    )
    parser.add_argument(
        "--source",
        default=None,
        help=(
            "URL or local path for MCC-MNC JSON. "
            "If omitted and --db exists with operators table, loads from DB. "
            "Otherwise fetches from GitHub."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Concurrent DNS probe workers (default: 10)",
    )
    parser.add_argument(
        "--dns-server",
        metavar="IP",
        help=(
            "DNS resolver IP to use. "
            "Set to your GRX/IPX resolver for full Diameter realm discovery."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit to first N operators (0 = no limit, useful for testing)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print summary of previously stored results and exit",
    )
    args = parser.parse_args()

    # Always init the DB (creates tables if missing)
    conn = init_db(args.db)

    if args.summary_only:
        print_summary(conn)
        conn.close()
        return

    # ── Resolve operator list ──────────────────────────────────────────────────
    if args.source:
        operators = load_operators_from_url(args.source)
    elif Path(args.db).exists():
        try:
            operators = load_operators_from_db(conn)
            if not operators:
                raise ValueError("operators table is empty")
            log.info("Loaded %d operators from database", len(operators))
        except Exception as exc:
            log.warning("Could not load operators from DB (%s); fetching from GitHub.", exc)
            operators = load_operators_from_url(MCC_MNC_URL)
    else:
        operators = load_operators_from_url(MCC_MNC_URL)

    if args.limit > 0:
        operators = operators[: args.limit]
        log.info("Limited to first %d operators", args.limit)

    total = len(operators)
    log.info("Loaded %d operators for Diameter realm probing", total)

    # ── DNS resolver ───────────────────────────────────────────────────────────
    resolver = make_resolver(args.dns_server)

    if not args.dns_server:
        log.warning(
            "No --dns-server specified — using public DNS. "
            "Diameter EPC realms live in GRX/IPX DNS; "
            "public results indicate misconfiguration (IR.88 finding)."
        )
    else:
        log.info("GRX/IPX resolver %s — full Diameter enumeration mode", args.dns_server)

    log.info(
        "Diameter scan | workers=%d | realm templates=%d | db=%s",
        args.workers, len(REALM_TEMPLATES), args.db,
    )

    # ── Concurrent probe loop ──────────────────────────────────────────────────
    completed = found_ops = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(probe_operator, item, resolver): item
            for item in operators
        }
        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                if result and result.get("realms"):
                    save_result(conn, result)
                    found_ops += 1
                    realm_list = ", ".join(r["realm"] for r in result["realms"])
                    log.info(
                        "[%d/%d] Diameter found — %s (%s): %s",
                        completed, total,
                        result["operator"], result["country_name"],
                        realm_list,
                    )
                elif completed % 500 == 0:
                    elapsed = time.time() - start
                    rate    = completed / max(elapsed, 0.01)
                    eta     = (total - completed) / max(rate, 0.01)
                    log.info(
                        "[%d/%d] %.1f ops/s | ETA %.0fs | Diameter operators found: %d",
                        completed, total, rate, eta, found_ops,
                    )
            except Exception as exc:
                log.debug("Worker error: %s", exc)

    elapsed = time.time() - start
    log.info(
        "Diameter scan done in %.1fs | %d operators with Diameter realms discovered",
        elapsed, found_ops,
    )
    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
