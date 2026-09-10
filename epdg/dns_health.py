"""Authoritative delegation and DNS posture checks."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

import dns.flags
import dns.resolver

HEALTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS dns_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn TEXT NOT NULL,
    resolver_name TEXT NOT NULL,
    ns_records TEXT NOT NULL DEFAULT '[]',
    soa_records TEXT NOT NULL DEFAULT '[]',
    cname_records TEXT NOT NULL DEFAULT '[]',
    dnssec_status TEXT NOT NULL,
    nameserver_health TEXT NOT NULL DEFAULT '{}',
    checked_at TIMESTAMP NOT NULL,
    UNIQUE(fqdn, resolver_name, checked_at)
);
CREATE INDEX IF NOT EXISTS idx_dns_health_fqdn ON dns_health(fqdn, checked_at);
"""


def init_health_db(conn: sqlite3.Connection) -> None:
    conn.executescript(HEALTH_SCHEMA)


def _query(resolver: dns.resolver.Resolver, fqdn: str, record_type: str) -> tuple[str, list[str], int | None, bool]:
    try:
        answer = resolver.resolve(fqdn, record_type, search=False, raise_on_no_answer=False, lifetime=6, want_dnssec=True)
        response = getattr(answer, "response", None)
        values = [rdata.to_text() for rdata in answer] if answer.rrset else []
        ttl = int(answer.rrset.ttl) if answer.rrset else None
        return "NOERROR" if values else "NODATA", values, ttl, bool(response and response.flags & dns.flags.AD)
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN", [], None, False
    except dns.resolver.NoNameservers:
        return "SERVFAIL", [], None, False
    except dns.resolver.Timeout:
        return "TIMEOUT", [], None, False
    except dns.resolver.NoAnswer:
        return "NODATA", [], None, False


def probe_health(fqdn: str, resolver: dns.resolver.Resolver, resolver_name: str) -> dict[str, Any]:
    ns_status, ns_records, _, ns_secure = _query(resolver, fqdn, "NS")
    soa_status, soa_records, _, soa_secure = _query(resolver, fqdn, "SOA")
    cname_status, cname_records, _, cname_secure = _query(resolver, fqdn, "CNAME")
    nameserver_health: dict[str, str] = {}
    for nameserver in ns_records:
        host = nameserver.rstrip(".")
        status, _, _, _ = _query(resolver, host, "A")
        nameserver_health[host] = status
    return {
        "fqdn": fqdn,
        "resolver_name": resolver_name,
        "ns_records": ns_records,
        "soa_records": soa_records,
        "cname_records": cname_records,
        "dnssec_status": "SECURE" if ns_secure or soa_secure or cname_secure else "INSECURE",
        "nameserver_health": nameserver_health,
        "ns_status": ns_status,
        "soa_status": soa_status,
        "cname_status": cname_status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def save_health(conn: sqlite3.Connection, result: dict[str, Any]) -> None:
    init_health_db(conn)
    conn.execute(
        """INSERT INTO dns_health
           (fqdn,resolver_name,ns_records,soa_records,cname_records,dnssec_status,
            nameserver_health,checked_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (result["fqdn"], result["resolver_name"], json.dumps(result["ns_records"]),
         json.dumps(result["soa_records"]), json.dumps(result["cname_records"]),
         result["dnssec_status"], json.dumps(result["nameserver_health"], sort_keys=True),
         result["checked_at"]),
    )
    conn.commit()
