#!/usr/bin/env python3
"""
GRX/IPX DNS Access Helper
━━━━━━━━━━━━━━━━━━━━━━━━━
Provides two practical approaches for private researchers to query GRX/IPX DNS:

  Method A — RIPE Atlas
    Uses RIPE Atlas probes deployed inside operator/ISP networks.
    Many probes are inside networks with GRX connectivity.
    Free account at https://atlas.ripe.net — 10,000 credits/day.
    DNS queries cost ~1 credit each.

  Method B — Open Resolver Discovery
    Some GRX DNS resolvers are misconfigured as open resolvers.
    Probes known GRX/IPX IP ranges for responsive DNS servers,
    then tests whether they resolve 5GC/GRX-specific FQDNs.
    Uses only passive DNS queries — no exploitation.

  Method C — Zone delegation walk
    Walks NS delegations for 3gppnetwork.org subzones to map the
    DNS infrastructure, then attempts AXFR on each authoritative NS.

LEGAL NOTE
──────────
All techniques here are passive DNS queries and authorised measurement
platforms. No credentials are bypassed, no systems are compromised.
RIPE Atlas is explicitly designed for this kind of research.
Open resolver probing sends standard DNS packets; treat any responding
server as a public service (RFC 5358 compliant servers will refuse
recursive queries from unauthorised sources).

Usage:
  # RIPE Atlas: create a 5GC DNS measurement from operator-ASN probes
  python3 3gpppub-grx-access.py atlas --key YOUR_API_KEY --fqdn nrf.5gc.mnc001.mcc234.3gppnetwork.org

  # Find operator-ASN probes suitable for GRX queries
  python3 3gpppub-grx-access.py atlas --key YOUR_API_KEY --list-probes --asn 12322

  # Probe known GRX IP ranges for open DNS resolvers
  python3 3gpppub-grx-access.py openresolver --ranges grx-ranges.txt

  # Walk NS delegations for 3gppnetwork.org 5GC subzones
  python3 3gpppub-grx-access.py zonewalk
"""

import argparse
import json
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network

import dns.query
import dns.resolver
import dns.rdatatype
import dns.zone
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

RIPE_ATLAS_API = "https://atlas.ripe.net/api/v2"

# ── Known GRX/IPX IP ranges (public info from GSMA IR.34, BGP tables, RIPE) ──
# These are example ranges; update from current GSMA IR.34 or RouteViews data.
# GRX address space was originally allocated around 192.3.x.x, 166.63.x.x
# and various ranges assigned to major IPX providers.
# Source: RIPE BGP data, GSMA IR.34 (public document), operator NOC contacts.

KNOWN_GRX_RANGES = [
    # These are illustrative — cross-reference with current GSMA IR.34 Annex
    # and BGP communities used by GRX providers (e.g., BICS AS6774,
    # Syniverse AS9505, Tata AS6453, NTT AS2914, Orange AS5511)
    "192.3.73.0/24",      # historical GRX range (GSMA allocated)
    "166.63.0.0/18",      # historical GRX range
    # Add ranges from current GSMA IR.34 or your IPX provider's allocation
]

# 5GC test FQDNs — if a resolver answers these, it has GRX DNS access
GRX_TEST_FQDNS = [
    "nrf.5gc.mnc001.mcc234.3gppnetwork.org",    # EE UK (well-known operator)
    "sepp.5gc.mnc001.mcc262.3gppnetwork.org",   # Telekom DE
    "nrf.5gc.mnc001.mcc208.3gppnetwork.org",    # Orange FR
    "nrf.grx.3gppnetwork.org",                  # GRX meta-zone itself
]

# ═══════════════════════════════════════════════════════════════════════
#  METHOD A — RIPE ATLAS
# ═══════════════════════════════════════════════════════════════════════

def atlas_list_probes(api_key: str, asn: int | None, status: int = 1,
                      limit: int = 100) -> list[dict]:
    """List RIPE Atlas probes, optionally filtered by ASN."""
    params = {"status": status, "format": "json", "page_size": limit}
    if asn:
        params["asn"] = asn
    headers = {"Authorization": f"Key {api_key}"} if api_key else {}
    resp = requests.get(f"{RIPE_ATLAS_API}/probes/", params=params,
                        headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("results", [])


def atlas_list_operator_probes(api_key: str, operator_asns: list[int]) -> list[dict]:
    """
    Find Atlas probes inside telecom operator ASNs.
    Prioritise ASNs of operators known to be GRX-connected.
    """
    all_probes = []
    for asn in operator_asns:
        probes = atlas_list_probes(api_key, asn=asn, limit=50)
        all_probes.extend(probes)
        log.info("ASN %d: %d probes", asn, len(probes))
    return all_probes


def atlas_create_dns_measurement(
    api_key: str,
    fqdn: str,
    record_type: str = "A",
    probe_ids: list[int] | None = None,
    use_probe_resolver: bool = True,
    custom_dns_server: str | None = None,
    description: str | None = None,
) -> dict:
    """
    Create a one-off RIPE Atlas DNS measurement.

    use_probe_resolver=True  → each probe uses its local resolver
                               (best for GRX: probes inside operator networks
                                will use their operator's GRX-connected resolver)
    custom_dns_server        → force a specific resolver IP
    """
    if not api_key:
        log.error("RIPE Atlas API key required for creating measurements.")
        log.info("Get a free key at https://atlas.ripe.net/accounts/register/")
        sys.exit(1)

    dns_kwargs: dict = {
        "type":           "dns",
        "af":             4,
        "query_class":    "IN",
        "query_type":     record_type.upper(),
        "query_argument": fqdn,
        "use_probe_resolver": use_probe_resolver,
        "set_rd_bit":     True,
        "retry":          2,
    }
    if custom_dns_server:
        dns_kwargs["target"]              = custom_dns_server
        dns_kwargs["use_probe_resolver"]  = False

    measurement_spec = {
        "definitions": [
            {
                **dns_kwargs,
                "description": description or f"3GPP 5GC DNS lookup: {fqdn}",
            }
        ],
        "probes": [
            {
                "type":  "probes",
                "value": ",".join(str(p) for p in probe_ids) if probe_ids else "1,2,3,4,5",
                "requested": len(probe_ids) if probe_ids else 5,
            }
            if probe_ids
            else {"type": "area", "value": "WW", "requested": 20}
        ],
        "is_oneoff": True,
        "bill_to": None,
    }

    resp = requests.post(
        f"{RIPE_ATLAS_API}/measurements/",
        json=measurement_spec,
        headers={"Authorization": f"Key {api_key}", "Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        log.error("Atlas API error %d: %s", resp.status_code, resp.text)
        sys.exit(1)

    result = resp.json()
    msm_ids = result.get("measurements", [])
    log.info("Measurement created: IDs %s", msm_ids)
    log.info("View at: https://atlas.ripe.net/measurements/%s/",
             msm_ids[0] if msm_ids else "?")
    return result


def atlas_get_results(api_key: str, measurement_id: int,
                      wait_secs: int = 60) -> list[dict]:
    """Poll for measurement results."""
    headers = {"Authorization": f"Key {api_key}"}
    log.info("Waiting %ds for measurement %d to complete...", wait_secs, measurement_id)
    time.sleep(wait_secs)

    resp = requests.get(
        f"{RIPE_ATLAS_API}/measurements/{measurement_id}/results/",
        headers=headers, timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def atlas_print_dns_results(results: list[dict], fqdn: str) -> None:
    print(f"\n── Atlas DNS Results for {fqdn} ─────────────────────────────────")
    grx_positive = []
    for r in results:
        probe_id = r.get("prb_id", "?")
        answers  = []
        abuf = r.get("result", {}).get("abuf", {}) if isinstance(r.get("result"), dict) else {}
        for ans in abuf.get("answers", []):
            answers.append(f"{ans.get('TYPE','?')} {ans.get('RDATA','?')}")

        rcode = abuf.get("HEADER", {}).get("RCODE", "?") if isinstance(abuf, dict) else "?"

        if answers:
            grx_positive.append((probe_id, answers))
            print(f"  ✅ Probe {probe_id:>6} | RCODE={rcode} | {' | '.join(answers)}")
        elif rcode == "NXDOMAIN":
            print(f"  ❌ Probe {probe_id:>6} | NXDOMAIN (resolver reached GRX but FQDN unknown)")
        else:
            print(f"  ⚪ Probe {probe_id:>6} | RCODE={rcode} (no answer — likely public DNS)")

    print(f"\n  {len(grx_positive)} probes returned answers (potential GRX resolvers)")
    if grx_positive:
        print("  Probe IDs with GRX resolution:", [p for p, _ in grx_positive])
        print("  → Use these probe IDs for future 5GC FQDN lookups")


# ═══════════════════════════════════════════════════════════════════════
#  METHOD B — OPEN RESOLVER DISCOVERY ON GRX RANGES
# ═══════════════════════════════════════════════════════════════════════

def test_dns_resolver(ip: str, test_fqdn: str, timeout: float = 2.0) -> dict:
    """
    Test if an IP responds as a DNS resolver and whether it has GRX access.
    Returns dict with 'responds', 'grx_capable', 'answer'.
    """
    result = {"ip": ip, "responds": False, "grx_capable": False,
              "answer": None, "rcode": None}
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.timeout     = timeout
        resolver.lifetime    = timeout * 2

        # First test: does it resolve at all?
        try:
            answers = resolver.resolve("google.com", "A")
            result["responds"] = bool(answers)
        except Exception:
            pass  # falls through to GRX test anyway

        # GRX test: does it resolve a 5GC/GRX-specific FQDN?
        try:
            answers = resolver.resolve(test_fqdn, "A")
            if answers:
                result["grx_capable"] = True
                result["answer"]      = [r.address for r in answers]
                log.info("  [GRX-CAPABLE] %s resolved %s → %s",
                         ip, test_fqdn, result["answer"])
        except dns.resolver.NXDOMAIN:
            # Resolver answered but FQDN not found — still GRX-capable
            result["responds"]    = True
            result["grx_capable"] = True
            result["rcode"]       = "NXDOMAIN"
            log.info("  [GRX-CAPABLE/NXDOMAIN] %s reached GRX DNS but FQDN unknown", ip)
        except Exception:
            pass

    except Exception:
        pass

    return result


def probe_grx_ranges(
    ip_ranges: list[str],
    test_fqdn: str,
    workers: int = 50,
    output_file: str | None = None,
) -> list[dict]:
    """Probe a list of CIDR ranges for GRX-capable open resolvers."""
    all_ips = []
    for cidr in ip_ranges:
        try:
            net = ip_network(cidr, strict=False)
            # Skip very large ranges to avoid accidental mass scanning
            if net.num_addresses > 65536:
                log.warning("Skipping large range %s (>65536 hosts). Split it.", cidr)
                continue
            all_ips.extend(str(ip) for ip in net.hosts())
        except ValueError as e:
            log.warning("Invalid range %s: %s", cidr, e)

    log.info("Probing %d IPs across %d ranges for GRX DNS...", len(all_ips), len(ip_ranges))

    grx_capable = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(test_dns_resolver, ip, test_fqdn): ip
            for ip in all_ips
        }
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if result["grx_capable"]:
                grx_capable.append(result)
            if i % 500 == 0:
                log.info("[%d/%d] GRX-capable found so far: %d", i, len(all_ips), len(grx_capable))

    log.info("Done. %d GRX-capable resolvers found out of %d IPs probed.",
             len(grx_capable), len(all_ips))

    if output_file:
        with open(output_file, "w") as f:
            json.dump(grx_capable, f, indent=2)
        log.info("Results saved to %s", output_file)

    return grx_capable


def load_ranges_from_file(path: str) -> list[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# ═══════════════════════════════════════════════════════════════════════
#  METHOD C — DNS ZONE DELEGATION WALK + AXFR PROBE
# ═══════════════════════════════════════════════════════════════════════

def get_ns_for_zone(zone: str) -> list[str]:
    """Return authoritative nameservers for a zone."""
    try:
        answers = dns.resolver.resolve(zone, "NS")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []


def resolve_ns_ips(ns_name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(ns_name, "A")
        return [r.address for r in answers]
    except Exception:
        return []


def try_axfr(zone: str, ns_ip: str, timeout: float = 10.0) -> list[str] | None:
    """Attempt a zone transfer. Returns records if successful, None if refused."""
    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, zone, timeout=timeout))
        records = []
        for name, node in z.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name}.{zone} {rdataset.ttl} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
        return records
    except Exception:
        return None


def zone_walk(zones: list[str]) -> None:
    """Walk NS delegations and probe AXFR for 3gppnetwork.org subzones."""
    print("\n── Zone Delegation Walk ──────────────────────────────────────────")
    for zone in zones:
        ns_names = get_ns_for_zone(zone)
        if not ns_names:
            print(f"  {zone:<55} — no NS found (not delegated / NXDOMAIN)")
            continue

        print(f"\n  {zone}")
        for ns_name in ns_names:
            ns_ips = resolve_ns_ips(ns_name)
            for ns_ip in ns_ips:
                print(f"    NS: {ns_name} ({ns_ip})")
                records = try_axfr(zone, ns_ip)
                if records is not None:
                    print(f"    ✅ AXFR SUCCESS — {len(records)} records")
                    for rec in records[:20]:
                        print(f"       {rec}")
                    if len(records) > 20:
                        print(f"       ... and {len(records)-20} more")
                else:
                    print("    ❌ AXFR refused")


# ═══════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════

# Well-known operator ASNs likely to have GRX-connected Atlas probes
OPERATOR_ASNS = [
    1273,  # Vodafone UK
    5607,  # Sky UK
    13184, # Telekom DE
    12322, # Free / Iliad FR
    3215,  # Orange FR
    5410,  # Bouygues Telecom FR
    6830,  # Liberty Global
    8220,  # Colt
    2856,  # BT UK
    3269,  # Telecom Italia
    12479, # Orange ES
    12430, # Vodafone ES
    6774,  # BICS (IPX provider) — direct GRX access
    9505,  # Syniverse (IPX provider) — direct GRX access
    6453,  # Tata Communications (IPX provider)
    2914,  # NTT (IPX provider)
]

# 3gppnetwork.org subzones to walk
ZONES_TO_WALK = [
    "3gppnetwork.org",
    "pub.3gppnetwork.org",
    "5gc.mnc001.mcc234.3gppnetwork.org",   # EE UK
    "5gc.mnc001.mcc262.3gppnetwork.org",   # Telekom DE
    "5gc.mnc001.mcc208.3gppnetwork.org",   # Orange FR
    "grx.3gppnetwork.org",
    "ims.3gppnetwork.org",
    "epc.mnc001.mcc234.3gppnetwork.org",
]


def main():
    parser = argparse.ArgumentParser(
        description="GRX/IPX DNS access helper for private researchers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="method", required=True)

    # Atlas subcommand
    p_atlas = sub.add_parser("atlas", help="Use RIPE Atlas probes for GRX DNS queries")
    p_atlas.add_argument("--key",            required=True, help="RIPE Atlas API key")
    p_atlas.add_argument("--fqdn",           help="FQDN to resolve")
    p_atlas.add_argument("--record-type",    default="A")
    p_atlas.add_argument("--probe-ids",      nargs="+", type=int, help="Specific probe IDs")
    p_atlas.add_argument("--asn",            type=int, help="Filter probes by ASN")
    p_atlas.add_argument("--list-probes",    action="store_true",
                         help="List probes in operator ASNs and exit")
    p_atlas.add_argument("--all-operator-asns", action="store_true",
                         help="Search probes in all known operator/IPX ASNs")
    p_atlas.add_argument("--wait",           type=int, default=60,
                         help="Seconds to wait for results (default: 60)")
    p_atlas.add_argument("--measurement-id", type=int,
                         help="Fetch results for an existing measurement")

    # Open resolver subcommand
    p_open = sub.add_parser("openresolver",
                             help="Probe GRX IP ranges for open DNS resolvers")
    p_open.add_argument("--ranges",   nargs="+",
                        default=KNOWN_GRX_RANGES, help="CIDR ranges to probe")
    p_open.add_argument("--ranges-file", help="File with one CIDR range per line")
    p_open.add_argument("--test-fqdn",
                        default=GRX_TEST_FQDNS[0], help="FQDN to test GRX resolution")
    p_open.add_argument("--workers",  type=int, default=50)
    p_open.add_argument("--output",   default="grx-resolvers.json")

    # Zone walk subcommand
    p_zone = sub.add_parser("zonewalk",
                             help="Walk NS delegations and probe AXFR")
    p_zone.add_argument("--zones", nargs="+", default=ZONES_TO_WALK)

    args = parser.parse_args()

    # ── RIPE Atlas ────────────────────────────────────────────────────
    if args.method == "atlas":
        if args.measurement_id:
            results = atlas_get_results(args.key, args.measurement_id, wait_secs=0)
            atlas_print_dns_results(results, args.fqdn or "?")
            return

        if args.list_probes or args.all_operator_asns:
            asns = OPERATOR_ASNS if args.all_operator_asns else ([args.asn] if args.asn else [])
            probes = atlas_list_operator_probes(args.key, asns)
            print(f"\n{'ID':>8}  {'ASN':>8}  {'Country':<4}  {'Status':<8}  Address")
            print("─" * 70)
            for p in probes:
                print(f"{p.get('id',0):>8}  {p.get('asn_v4',0):>8}  "
                      f"{p.get('country_code','??'):<4}  "
                      f"{p.get('status',{}).get('name','?'):<8}  "
                      f"{p.get('address_v4','')}")
            print(f"\n{len(probes)} probes found.")
            print("Tip: probes inside IPX provider ASNs (6774 BICS, 9505 Syniverse, "
                  "6453 Tata, 2914 NTT) have the best chance of GRX DNS access.")
            return

        if not args.fqdn:
            parser.error("--fqdn required when creating a measurement")

        probe_ids = args.probe_ids
        if not probe_ids and args.asn:
            probes    = atlas_list_probes(args.key, asn=args.asn, limit=20)
            probe_ids = [p["id"] for p in probes if p.get("status", {}).get("id") == 1]
            log.info("Using %d probes from ASN %d", len(probe_ids), args.asn)

        result   = atlas_create_dns_measurement(
            args.key, args.fqdn, args.record_type, probe_ids,
        )
        msm_ids  = result.get("measurements", [])
        if msm_ids:
            results = atlas_get_results(args.key, msm_ids[0], wait_secs=args.wait)
            atlas_print_dns_results(results, args.fqdn)

    # ── Open Resolver Discovery ───────────────────────────────────────
    elif args.method == "openresolver":
        ranges = args.ranges
        if args.ranges_file:
            ranges = load_ranges_from_file(args.ranges_file)

        print(f"\nProbing {len(ranges)} IP range(s) for GRX-capable resolvers")
        print(f"Test FQDN: {args.test_fqdn}")
        print(
            "\nNOTE: This sends standard DNS queries only. Any resolver that\n"
            "responds is acting as a public service. No exploitation involved.\n"
        )

        found = probe_grx_ranges(ranges, args.test_fqdn, args.workers, args.output)

        if found:
            print(f"\n{'═'*60}")
            print(f"  GRX-capable open resolvers found: {len(found)}")
            print(f"{'═'*60}")
            for r in found:
                status = f"→ {r['answer']}" if r['answer'] else "(NXDOMAIN — reached GRX)"
                print(f"  {r['ip']:<20}  {status}")
            print("\nUse any of these IPs with:")
            print("  python3 3gpppub-5g-discovery.py --dns-server <IP>")
        else:
            print("\nNo GRX-capable open resolvers found in the probed ranges.")
            print("Try updating the IP ranges from current GSMA IR.34 data.")

    # ── Zone Walk ─────────────────────────────────────────────────────
    elif args.method == "zonewalk":
        print(f"Walking {len(args.zones)} zone(s)...")
        zone_walk(args.zones)


if __name__ == "__main__":
    main()
