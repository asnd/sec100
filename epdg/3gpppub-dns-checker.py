#!/usr/bin/env python3
"""
3GPP Public Domain DNS Checker (lightweight, no database)
Prints discovered FQDNs to stdout and optionally to a file.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import dns.resolver
import requests
from dns.resolver import NXDOMAIN, NoAnswer, Timeout

sys.path.insert(0, str(Path(__file__).parent))
from subdomains import SUBDOMAINS
from normalize import normalize_entry

PARENT_DOMAIN = "pub.3gppnetwork.org"
MCC_MNC_URL = "https://raw.githubusercontent.com/pbakondy/mcc-mnc-list/master/mcc-mnc-list.json"


def resolve(fqdn: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(fqdn, rtype)
        return [r.address for r in answers]
    except (NXDOMAIN, NoAnswer, Timeout):
        return []
    except Exception:
        return []


def check_operator(mnc: int, mcc: int, subdomains: list[str], ipv6: bool) -> list[tuple]:
    """Return list of (fqdn, record_type, ips) for found records."""
    found = []
    rtypes = ["A", "AAAA"] if ipv6 else ["A"]
    for subdomain in subdomains:
        fqdn = f"{subdomain}.mnc{mnc:03d}.mcc{mcc:03d}.{PARENT_DOMAIN}"
        for rtype in rtypes:
            ips = resolve(fqdn, rtype)
            if ips:
                found.append((fqdn, rtype, ips))
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Check 3GPP public DNS records for all known MCC/MNC pairs."
    )
    parser.add_argument("--output", "-o", help="Write results to this file")
    parser.add_argument("--ipv6", action="store_true", help="Also check AAAA records")
    parser.add_argument(
        "--subdomains", nargs="+", default=SUBDOMAINS,
        help="Subdomains to probe"
    )
    parser.add_argument(
        "--source", default=MCC_MNC_URL,
        help="MCC/MNC list URL or local JSON path"
    )
    parser.add_argument(
        "--delay", type=float, default=0.0,
        help="Seconds to sleep between operators (default: 0)"
    )
    args = parser.parse_args()

    out = open(args.output, "w") if args.output else None

    def emit(line: str):
        print(line)
        if out:
            out.write(line + "\n")

    print(f"Fetching MCC/MNC list from {args.source} ...", file=sys.stderr)
    if args.source.startswith("http"):
        resp = requests.get(args.source, timeout=30)
        resp.raise_for_status()
        mcc_mnc_list = resp.json()
    else:
        with open(args.source) as f:
            mcc_mnc_list = json.load(f)

    total = len(mcc_mnc_list)
    print(f"Loaded {total} entries. Scanning ...\n", file=sys.stderr)

    found_total = 0
    for i, item in enumerate(mcc_mnc_list, 1):
        entry = normalize_entry(item)
        if entry is None:
            continue

        try:
            mcc = int(entry["mcc"])
            mnc = int(entry["mnc"])
        except (KeyError, ValueError):
            continue

        country  = entry.get("countryName", "?")
        operator = entry.get("operator", "?")

        if i % 200 == 0:
            print(f"[{i}/{total}] {country} — {operator}", file=sys.stderr)

        results = check_operator(mnc, mcc, args.subdomains, args.ipv6)
        for fqdn, rtype, ips in results:
            line = f"{rtype}\t{fqdn}\t{','.join(ips)}\t{country}\t{operator}"
            emit(line)
            found_total += 1

        if args.delay:
            time.sleep(args.delay)

    print(f"\nDone. {found_total} records found.", file=sys.stderr)
    if out:
        out.close()
        print(f"Results written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
