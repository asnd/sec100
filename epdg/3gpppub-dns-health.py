#!/usr/bin/env python3
"""Check authoritative NS, SOA, CNAME and DNSSEC delegation health."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

import dns.resolver

sys.path.insert(0, str(Path(__file__).parent))
from dns_health import probe_health, save_health


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fqdn")
    parser.add_argument("--resolver", default="system", metavar="NAME[=IP]")
    parser.add_argument("--db", default="database.db")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    resolver = dns.resolver.Resolver()
    name = args.resolver
    if "=" in args.resolver:
        name, address = args.resolver.split("=", 1)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [address]
    result = probe_health(args.fqdn, resolver, name)
    conn = sqlite3.connect(args.db)
    save_health(conn, result)
    print(json.dumps(result, indent=2) if args.json else
          f"{args.fqdn}: NS={result['ns_status']} SOA={result['soa_status']} "
          f"CNAME={result['cname_status']} DNSSEC={result['dnssec_status']}")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
