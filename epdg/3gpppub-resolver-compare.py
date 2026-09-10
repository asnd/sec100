#!/usr/bin/env python3
"""Compare DNS answers and DNSSEC state across configured resolvers."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

import dns.resolver

sys.path.insert(0, str(Path(__file__).parent))
from resolver_observations import compare_latest, init_observation_db, probe_fqdn, save_observation


def resolver_from_spec(spec: str) -> tuple[str, dns.resolver.Resolver]:
    if "=" in spec:
        name, address = spec.split("=", 1)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [address]
        return name, resolver
    return spec, dns.resolver.Resolver()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fqdn")
    parser.add_argument("--record-type", default="A", choices=("A", "AAAA", "CNAME", "NAPTR", "SRV"))
    parser.add_argument("--resolver", action="append", default=["system"], metavar="NAME[=IP]",
                        help="Resolver identity and optional nameserver address; repeatable")
    parser.add_argument("--source-asn")
    parser.add_argument("--source-country")
    parser.add_argument("--db", default="database.db")
    parser.add_argument("--json", action="store_true", help="Print all latest observations as JSON")
    args = parser.parse_args()
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    init_observation_db(conn)
    for spec in args.resolver:
        name, resolver = resolver_from_spec(spec)
        save_observation(conn, probe_fqdn(args.fqdn, args.record_type, resolver, name, args.source_asn, args.source_country))
    rows = compare_latest(conn, args.fqdn, args.record_type)
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(f"{row['resolver_name']}: {row['response_code']} {row['dnssec_status']} ttl={row['ttl']} answers={row['answers']}")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
