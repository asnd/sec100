#!/usr/bin/env python3
"""
Feature 2: 5G SA (Standalone) Domain Discovery
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DNS REACHABILITY CONTEXT
─────────────────────────
3GPP defines two distinct DNS zones with very different reachability:

  pub.3gppnetwork.org          ← PUBLIC internet DNS (our main scanner)
    Services: ims, epdg.epc, bsf, gan, xcap.ims
    Reachable from: anywhere on the internet ✅

  5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org   ← GRX / IPX private DNS
    Services: nrf, sepp, amf, smf, ausf, udm, pcf, nssf, scp …
    Reachable from: GRX/IPX networks only (requires operator membership) ⚠️

GRX (GPRS Roaming eXchange) and IPX (IP Packet eXchange) are the private
inter-operator backbones operated by BICS, Syniverse, Tata Comm, NTT, Orange,
TOFANE Global, etc.  Their DNS resolvers are not accessible from the open
internet by design (GSMA PRD IR.34, IR.67, IR.88).

WHAT CAN STILL BE DISCOVERED FROM PUBLIC DNS
──────────────────────────────────────────────
1. SEPP / NRF under pub.3gppnetwork.org
   Some operators mistakenly or deliberately publish their SEPP (Security Edge
   Protection Proxy) in the *public* zone.  Pattern:
     sepp.pub.3gppnetwork.org  (non-standard but observed)
     sepp.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org

2. Leak / dual-publish
   A subset of operators configure their 5GC NF records in both zones.
   Probing public DNS for 5gc.* still yields positive results from these.

3. NRF / SEPP TLS TLSA (DANE) records
   Some operators publish TLSA records in public DNS for SEPP N32 TLS
   certificate verification even though the SEPP itself is on IPX.

4. SRV _n32._tcp.<sepp-fqdn>
   The N32 interface uses SRV records that some operators publish publicly.

GRX/IPX ACCESS
───────────────
If you have GRX/IPX connectivity (operator, research peering, academic lab):
  --dns-server <GRX_RESOLVER_IP>   point at your GRX resolver
  --dns-server 185.89.218.1        example: BICS GRX resolver (illustrative)

Common GRX DNS resolver ranges (connect via GRX link first):
  Various per-IPX-provider, typically documented in GSMA IR.67 Annex

Usage:
  # Probe public DNS only (finds partial results)
  python3 3gpppub-5g-discovery.py

  # Probe via GRX resolver (if you have GRX access)
  python3 3gpppub-5g-discovery.py --dns-server <GRX_IP>

  # Check only SEPP + NRF (most likely to appear in public DNS)
  python3 3gpppub-5g-discovery.py --nf-types sepp nrf

  # Full scan including pub-zone SEPP patterns
  python3 3gpppub-5g-discovery.py --include-pub-zone

  # Summary of what was found
  python3 3gpppub-5g-discovery.py --summary-only
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("5g-scan.log")],
)
log = logging.getLogger(__name__)

MCC_MNC_URL = "https://raw.githubusercontent.com/pbakondy/mcc-mnc-list/master/mcc-mnc-list.json"

# ── Domain templates ──────────────────────────────────────────────────────────

# Primary 5GC zone (3GPP TS 23.003 §28) — lives in GRX/IPX DNS
DOMAIN_5GC = "5gc.mnc{mnc:03d}.mcc{mcc:03d}.3gppnetwork.org"

# Patterns observed in the wild under pub.3gppnetwork.org
# (non-standard but some operators publish SEPP/NRF here too)
DOMAIN_PUB = "mnc{mnc:03d}.mcc{mcc:03d}.pub.3gppnetwork.org"

# NF types defined in 3GPP TS 23.003 §28 + TS 29.510
DEFAULT_NF_TYPES = ["nrf", "sepp", "amf", "smf", "ausf", "udm", "pcf", "nssf", "scp"]

# NFs most likely to appear in *public* DNS (either by design or misconfiguration)
PUBLIC_LIKELY_NF_TYPES = ["sepp", "nrf"]

NF_DESCRIPTIONS = {
    "nrf":  "Network Repository Function       — 5G SA live indicator",
    "sepp": "Security Edge Protection Proxy    — 5G roaming/interconnect",
    "amf":  "Access & Mobility Management Fn   — 5G RAN connectivity",
    "smf":  "Session Management Function       — 5G data plane",
    "ausf": "Authentication Server Function    — 5G UE authentication",
    "udm":  "Unified Data Management           — subscriber database",
    "pcf":  "Policy Control Function           — 5G QoS/charging",
    "nssf": "Network Slice Selection Function  — network slicing",
    "scp":  "Service Communication Proxy       — advanced NF mesh",
}

SCHEMA_5G = """
CREATE TABLE IF NOT EXISTS fiveg_fqdns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mnc          INTEGER NOT NULL,
    mcc          INTEGER NOT NULL,
    operator     TEXT,
    country_name TEXT,
    nf_type      TEXT    NOT NULL,
    fqdn         TEXT    NOT NULL,
    record_type  TEXT    NOT NULL DEFAULT 'A',
    resolved_ips TEXT,
    dns_zone     TEXT,   -- '5gc' or 'pub' or 'tlsa' or 'srv'
    dns_server   TEXT,   -- resolver used ('public' or IP of GRX resolver)
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMP,
    UNIQUE(fqdn, record_type)
);
CREATE INDEX IF NOT EXISTS idx_5g_country ON fiveg_fqdns(country_name);
CREATE INDEX IF NOT EXISTS idx_5g_nftype  ON fiveg_fqdns(nf_type);
CREATE INDEX IF NOT EXISTS idx_5g_zone    ON fiveg_fqdns(dns_zone);
"""


def make_resolver(dns_server: str | None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout  = 3
    r.lifetime = 6
    if dns_server:
        r.nameservers = [dns_server]
        log.info("Using custom DNS server: %s", dns_server)
    return r


def resolve_fqdn(
    fqdn: str, rtype: str, resolver: dns.resolver.Resolver, retries: int = 1
) -> list[str]:
    for attempt in range(retries + 1):
        try:
            answers = resolver.resolve(fqdn, rtype)
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


def resolve_tlsa(fqdn: str, resolver: dns.resolver.Resolver) -> list[str]:
    """Query DANE TLSA record — published in public DNS even if SEPP is on IPX."""
    tlsa_name = f"_443._tcp.{fqdn}"
    try:
        answers = resolver.resolve(tlsa_name, "TLSA")
        return [str(r) for r in answers]
    except Exception:
        return []


def resolve_srv_n32(fqdn: str, resolver: dns.resolver.Resolver) -> list[str]:
    """Query SRV for N32 (SEPP inter-PLMN) interface."""
    srv_name = f"_n32._tcp.{fqdn}"
    try:
        answers = resolver.resolve(srv_name, "SRV")
        return [f"{r.priority} {r.weight} {r.port} {r.target}" for r in answers]
    except Exception:
        return []


def probe_operator_5g(
    item: dict,
    nf_types: list[str],
    record_types: list[str],
    resolver: dns.resolver.Resolver,
    dns_server_label: str,
    include_pub_zone: bool,
) -> dict:
    try:
        mcc = int(item["mcc"])
        mnc = int(item["mnc"])
    except (KeyError, ValueError):
        return {}

    operator     = item.get("operator", "Unknown")
    country_name = item.get("countryName", "Unknown")

    base_5gc = DOMAIN_5GC.format(mnc=mnc, mcc=mcc)
    base_pub = DOMAIN_PUB.format(mnc=mnc, mcc=mcc)

    found = []

    # ── 5GC zone (works well on GRX, hit-or-miss on public) ──────────────────
    for nf in nf_types:
        fqdn = f"{nf}.{base_5gc}"
        for rtype in record_types:
            ips = resolve_fqdn(fqdn, rtype, resolver)
            if ips:
                found.append({
                    "nf_type":    nf,
                    "fqdn":       fqdn,
                    "record_type": rtype,
                    "resolved_ips": ",".join(ips),
                    "dns_zone":   "5gc",
                })
                log.info("  [5GC] [+] %s %s → %s", rtype, fqdn, ", ".join(ips))

        # DANE TLSA for SEPP (often published in public DNS)
        if nf == "sepp":
            tlsa = resolve_tlsa(fqdn, resolver)
            if tlsa:
                found.append({
                    "nf_type":    "sepp",
                    "fqdn":       fqdn,
                    "record_type": "TLSA",
                    "resolved_ips": " | ".join(tlsa),
                    "dns_zone":   "tlsa",
                })
                log.info("  [TLSA] [+] SEPP TLSA %s → %d records", fqdn, len(tlsa))

            srv = resolve_srv_n32(fqdn, resolver)
            if srv:
                found.append({
                    "nf_type":    "sepp",
                    "fqdn":       fqdn,
                    "record_type": "SRV",
                    "resolved_ips": " | ".join(srv),
                    "dns_zone":   "srv",
                })
                log.info("  [SRV]  [+] SEPP N32 %s → %s", fqdn, srv)

    # ── pub zone — non-standard but observed in the wild ─────────────────────
    if include_pub_zone:
        for nf in PUBLIC_LIKELY_NF_TYPES:
            if nf not in nf_types:
                continue
            fqdn = f"{nf}.{base_pub}"
            for rtype in record_types:
                ips = resolve_fqdn(fqdn, rtype, resolver)
                if ips:
                    found.append({
                        "nf_type":    nf,
                        "fqdn":       fqdn,
                        "record_type": rtype,
                        "resolved_ips": ",".join(ips),
                        "dns_zone":   "pub",
                    })
                    log.info("  [PUB]  [+] %s %s → %s (pub-zone leak!)", rtype, fqdn, ", ".join(ips))

    return {
        "mnc": mnc, "mcc": mcc,
        "operator": operator, "country_name": country_name,
        "dns_server": dns_server_label,
        "found": found,
    }


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_5G)
    conn.commit()
    return conn


def save_5g_result(conn: sqlite3.Connection, result: dict) -> None:
    if not result or not result.get("found"):
        return
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        for entry in result["found"]:
            conn.execute(
                """
                INSERT INTO fiveg_fqdns
                    (mnc, mcc, operator, country_name, nf_type, fqdn,
                     record_type, resolved_ips, dns_zone, dns_server,
                     first_seen, last_seen)
                VALUES
                    (:mnc, :mcc, :operator, :country_name, :nf_type, :fqdn,
                     :record_type, :resolved_ips, :dns_zone, :dns_server,
                     :now, :now)
                ON CONFLICT(fqdn, record_type) DO UPDATE SET
                    resolved_ips = excluded.resolved_ips,
                    last_seen    = excluded.last_seen
                """,
                {
                    "mnc":          result["mnc"],
                    "mcc":          result["mcc"],
                    "operator":     result["operator"],
                    "country_name": result["country_name"],
                    "nf_type":      entry["nf_type"],
                    "fqdn":         entry["fqdn"],
                    "record_type":  entry["record_type"],
                    "resolved_ips": entry["resolved_ips"],
                    "dns_zone":     entry["dns_zone"],
                    "dns_server":   result["dns_server"],
                    "now":          now,
                },
            )


def load_operators(source: str) -> list[dict]:
    if source.startswith("http"):
        resp = requests.get(source, timeout=30)
        resp.raise_for_status()
        return resp.json()
    with open(source) as f:
        return json.load(f)


def print_summary(conn: sqlite3.Connection) -> None:
    total = conn.execute("SELECT COUNT(*) FROM fiveg_fqdns").fetchone()[0]
    if total == 0:
        print("\n  No 5G SA NF records found.")
        print("  NOTE: Most 5GC NF records live in GRX/IPX DNS, not public DNS.")
        print("        Use --dns-server <GRX_IP> if you have GRX/IPX access.")
        return

    print(f"\n{'═'*68}")
    print("  5G SA Discovery Summary")
    print(f"{'═'*68}")
    print(f"  Total 5GC records: {total}")

    zone_rows = conn.execute(
        "SELECT dns_zone, COUNT(*) FROM fiveg_fqdns GROUP BY dns_zone ORDER BY COUNT(*) DESC"
    ).fetchall()
    print("\n── By DNS Zone ───────────────────────────────────────────────────")
    zone_labels = {"5gc": "5GC zone (GRX/IPX)", "pub": "pub zone (public, non-std)",
                   "tlsa": "TLSA (DANE, public)", "srv": "SRV N32 (SEPP)"}
    for zone, cnt in zone_rows:
        print(f"  {zone_labels.get(zone, zone):<35} {cnt:>5} records")

    print("\n── By NF Type ───────────────────────────────────────────────────")
    nf_rows = conn.execute(
        """
        SELECT nf_type, COUNT(DISTINCT mcc || '-' || mnc) AS operators, COUNT(*) AS records
        FROM fiveg_fqdns GROUP BY nf_type ORDER BY operators DESC
        """
    ).fetchall()
    for row in nf_rows:
        desc = NF_DESCRIPTIONS.get(row[0], "")
        print(f"  {row[0]:<6}  {row[1]:>4} operators  {row[2]:>5} records  {desc}")

    print("\n── Top Countries ────────────────────────────────────────────────")
    ctry_rows = conn.execute(
        """
        SELECT country_name,
               COUNT(DISTINCT mcc || '-' || mnc) AS operators,
               GROUP_CONCAT(DISTINCT nf_type)    AS nf_types,
               GROUP_CONCAT(DISTINCT dns_zone)   AS zones
        FROM fiveg_fqdns
        GROUP BY country_name
        ORDER BY operators DESC LIMIT 15
        """
    ).fetchall()
    for row in ctry_rows:
        print(f"  {row[0]:<35} {row[1]:>3} ops  NFs: {row[2]}  zones: {row[3]}")

    sepp_rows = conn.execute(
        """
        SELECT operator, country_name, fqdn, resolved_ips, dns_zone
        FROM fiveg_fqdns WHERE nf_type = 'sepp' ORDER BY country_name
        """
    ).fetchall()
    if sepp_rows:
        print("\n── SEPP Endpoints (5G Roaming Ready) ───────────────────────────")
        for row in sepp_rows:
            print(f"  [{row['dns_zone']:<4}] {row['country_name']:<25} {row['operator']:<35} {row['resolved_ips']}")


def main():
    parser = argparse.ArgumentParser(
        description="Discover 5G SA NF FQDNs via public DNS or GRX/IPX resolver.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DNS Zone Notes:
  Public DNS  → finds operators that publish 5GC records publicly (rare but real)
  GRX/IPX DNS → full discovery, requires --dns-server <GRX_RESOLVER_IP>
                 and connectivity to a GRX/IPX network

  Most 5GC NF records (NRF, AMF, SMF…) only exist in GRX/IPX DNS.
  SEPP DANE/TLSA and some SEPP A records may be in public DNS.
        """,
    )
    parser.add_argument("--db",       default="database.db")
    parser.add_argument("--source",   default=MCC_MNC_URL)
    parser.add_argument("--workers",  type=int, default=15)
    parser.add_argument("--ipv6",     action="store_true", help="Also probe AAAA records")
    parser.add_argument(
        "--dns-server", metavar="IP",
        help="DNS resolver IP to use. Set to your GRX/IPX resolver for full 5GC discovery.",
    )
    parser.add_argument(
        "--nf-types", nargs="+", default=DEFAULT_NF_TYPES, metavar="NF",
        help=f"NF types to probe (default: {' '.join(DEFAULT_NF_TYPES)})",
    )
    parser.add_argument(
        "--include-pub-zone", action="store_true",
        help="Also probe sepp/nrf under pub.3gppnetwork.org (non-standard patterns)",
    )
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()

    conn = init_db(args.db)

    if args.summary_only:
        print_summary(conn)
        conn.close()
        return

    resolver         = make_resolver(args.dns_server)
    dns_server_label = args.dns_server or "public"
    record_types     = ["A", "AAAA"] if args.ipv6 else ["A"]

    if not args.dns_server:
        log.warning(
            "No --dns-server specified. Using public DNS. "
            "5GC NF records primarily live in GRX/IPX DNS — "
            "results will be sparse without GRX access."
        )
        log.info(
            "Tip: use --nf-types sepp nrf --include-pub-zone for best public DNS coverage."
        )
    else:
        log.info("GRX/IPX resolver: %s — full 5GC discovery mode", args.dns_server)

    log.info(
        "5G scan | workers=%d | NF types=%s | record_types=%s | pub_zone=%s",
        args.workers, args.nf_types, record_types, args.include_pub_zone,
    )

    operators = load_operators(args.source)
    total     = len(operators)
    log.info("Loaded %d operators", total)

    completed = found_ops = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                probe_operator_5g, item, args.nf_types, record_types,
                resolver, dns_server_label, args.include_pub_zone,
            ): item
            for item in operators
        }
        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                if result and result.get("found"):
                    save_5g_result(conn, result)
                    found_ops += 1
                    nf_list = ", ".join(
                        f"{e['nf_type']}[{e['dns_zone']}]" for e in result["found"]
                    )
                    log.info(
                        "[%d/%d] 5G found — %s (%s): %s",
                        completed, total,
                        result["operator"], result["country_name"], nf_list,
                    )
                elif completed % 500 == 0:
                    elapsed = time.time() - start
                    eta = (total - completed) / max(completed / elapsed, 0.01)
                    log.info(
                        "[%d/%d] ETA %.0fs | 5G-capable operators so far: %d",
                        completed, total, eta, found_ops,
                    )
            except Exception as exc:
                log.debug("Worker error: %s", exc)

    elapsed = time.time() - start
    log.info("5G scan done in %.1fs | %d operators with 5GC NFs discovered", elapsed, found_ops)
    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
