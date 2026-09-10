"""Resolver-aware DNS observations for comparison across vantage points."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

import dns.flags
import dns.resolver

OBSERVATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS dns_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn TEXT NOT NULL,
    record_type TEXT NOT NULL,
    resolver_name TEXT NOT NULL,
    resolver_address TEXT,
    source_asn TEXT,
    source_country TEXT,
    response_code TEXT NOT NULL,
    dnssec_status TEXT NOT NULL,
    ttl INTEGER,
    answers TEXT NOT NULL DEFAULT '[]',
    observed_at TIMESTAMP NOT NULL,
    UNIQUE(fqdn, record_type, resolver_name, observed_at)
);
CREATE INDEX IF NOT EXISTS idx_dns_obs_fqdn ON dns_observations(fqdn, record_type);
CREATE INDEX IF NOT EXISTS idx_dns_obs_resolver ON dns_observations(resolver_name, observed_at);
"""


def init_observation_db(conn: sqlite3.Connection) -> None:
    conn.executescript(OBSERVATION_SCHEMA)


def _resolver_address(resolver: dns.resolver.Resolver) -> str | None:
    nameservers = getattr(resolver, "nameservers", None) or []
    return ",".join(str(server) for server in nameservers) or None


def probe_fqdn(
    fqdn: str,
    record_type: str,
    resolver: dns.resolver.Resolver,
    resolver_name: str,
    source_asn: str | None = None,
    source_country: str | None = None,
) -> dict[str, Any]:
    """Probe one name and normalize response, DNSSEC, TTL and answers."""
    observed_at = datetime.now(timezone.utc).isoformat()
    result: dict[str, Any] = {
        "fqdn": fqdn,
        "record_type": record_type,
        "resolver_name": resolver_name,
        "resolver_address": _resolver_address(resolver),
        "source_asn": source_asn,
        "source_country": source_country,
        "response_code": "ERROR",
        "dnssec_status": "UNKNOWN",
        "ttl": None,
        "answers": [],
        "observed_at": observed_at,
    }
    try:
        answer = resolver.resolve(
            fqdn,
            record_type,
            search=False,
            raise_on_no_answer=False,
            lifetime=6,
            **({"want_dnssec": True} if record_type in {"A", "AAAA", "NAPTR", "SRV", "CNAME"} else {}),
        )
        response = getattr(answer, "response", None)
        result["response_code"] = "NOERROR"
        result["dnssec_status"] = "SECURE" if response and response.flags & dns.flags.AD else "INSECURE"
        if answer.rrset is not None:
            result["ttl"] = int(answer.rrset.ttl)
            result["answers"] = [rdata.to_text() for rdata in answer]
        elif not result["answers"]:
            result["response_code"] = "NODATA"
    except dns.resolver.NXDOMAIN:
        result["response_code"] = "NXDOMAIN"
        result["dnssec_status"] = "INSECURE"
    except dns.resolver.NoNameservers:
        result["response_code"] = "SERVFAIL"
    except dns.resolver.NoAnswer:
        result["response_code"] = "NODATA"
        result["dnssec_status"] = "INSECURE"
    except dns.resolver.Timeout:
        result["response_code"] = "TIMEOUT"
    return result


def save_observation(conn: sqlite3.Connection, observation: dict[str, Any]) -> None:
    init_observation_db(conn)
    conn.execute(
        """INSERT INTO dns_observations
           (fqdn,record_type,resolver_name,resolver_address,source_asn,source_country,
            response_code,dnssec_status,ttl,answers,observed_at)
           VALUES (:fqdn,:record_type,:resolver_name,:resolver_address,:source_asn,
                   :source_country,:response_code,:dnssec_status,:ttl,:answers,:observed_at)
           ON CONFLICT(fqdn,record_type,resolver_name,observed_at) DO UPDATE SET
             response_code=excluded.response_code, dnssec_status=excluded.dnssec_status,
             ttl=excluded.ttl, answers=excluded.answers""",
        {**observation, "answers": json.dumps(observation.get("answers", []), sort_keys=True)},
    )
    conn.commit()


def compare_latest(conn: sqlite3.Connection, fqdn: str, record_type: str = "A") -> list[dict[str, Any]]:
    """Return latest observation per resolver for a name/type."""
    init_observation_db(conn)
    rows = conn.execute(
        """SELECT o.* FROM dns_observations o
           JOIN (SELECT resolver_name, MAX(observed_at) observed_at
                 FROM dns_observations WHERE fqdn=? AND record_type=? GROUP BY resolver_name) latest
             ON latest.resolver_name=o.resolver_name AND latest.observed_at=o.observed_at
           WHERE o.fqdn=? AND o.record_type=? ORDER BY o.resolver_name""",
        (fqdn, record_type, fqdn, record_type),
    ).fetchall()
    return [dict(row) for row in rows]
