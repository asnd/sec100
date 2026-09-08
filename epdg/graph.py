"""Build and query a relationship graph from the discovery database.

The graph is a materialized view of current observations.  Nodes and edges are
kept across rebuilds with ``active`` flags so exports can be compared over
time without adding a graph database dependency.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from typing import Any

GRAPH_SCHEMA = """
CREATE TABLE IF NOT EXISTS graph_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_type TEXT NOT NULL,
    node_key TEXT NOT NULL,
    label TEXT,
    metadata TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(node_type, node_key)
);
CREATE TABLE IF NOT EXISTS graph_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES graph_nodes(id),
    relationship TEXT NOT NULL,
    target_id INTEGER NOT NULL REFERENCES graph_nodes(id),
    metadata TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_id, relationship, target_id)
);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_active ON graph_nodes(active, node_type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_active ON graph_edges(active, relationship);
"""


def init_graph(conn: sqlite3.Connection) -> None:
    conn.executescript(GRAPH_SCHEMA)


def _json(value: dict[str, Any] | None) -> str | None:
    return json.dumps(value, sort_keys=True) if value else None


def _node(conn: sqlite3.Connection, kind: str, key: str, label: str | None = None,
          metadata: dict[str, Any] | None = None) -> int:
    conn.execute(
        """INSERT INTO graph_nodes(node_type,node_key,label,metadata,active,last_seen)
           VALUES(?,?,?,?,1,CURRENT_TIMESTAMP)
           ON CONFLICT(node_type,node_key) DO UPDATE SET
             label=COALESCE(excluded.label, graph_nodes.label),
             metadata=COALESCE(excluded.metadata, graph_nodes.metadata),
             active=1, last_seen=CURRENT_TIMESTAMP""",
        (kind, key, label or key, _json(metadata)),
    )
    return conn.execute(
        "SELECT id FROM graph_nodes WHERE node_type=? AND node_key=?", (kind, key)
    ).fetchone()[0]


def _edge(conn: sqlite3.Connection, source: int, relation: str, target: int,
          metadata: dict[str, Any] | None = None) -> None:
    conn.execute(
        """INSERT INTO graph_edges(source_id,relationship,target_id,metadata,active,last_seen)
           VALUES(?,?,?,?,1,CURRENT_TIMESTAMP)
           ON CONFLICT(source_id,relationship,target_id) DO UPDATE SET
             metadata=COALESCE(excluded.metadata, graph_edges.metadata),
             active=1, last_seen=CURRENT_TIMESTAMP""",
        (source, relation, target, _json(metadata)),
    )


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def build_graph(conn: sqlite3.Connection) -> dict[str, int]:
    """Materialize active PLMN/service/FQDN/IP/ASN/provider relationships."""
    init_graph(conn)
    conn.execute("UPDATE graph_nodes SET active=0")
    conn.execute("UPDATE graph_edges SET active=0")
    rows = conn.execute(
        """SELECT mnc,mcc,operator,country_name,fqdn,record_type,service,resolved_ips
           FROM available_fqdns WHERE COALESCE(dns_status,'ANSWERED')='ANSWERED'"""
    ).fetchall() if _table_exists(conn, "available_fqdns") else []
    for row in rows:
        mnc, mcc, operator, country, fqdn, record_type, service, resolved = row
        plmn_key = f"mcc{int(mcc):03d}-mnc{int(mnc):03d}"
        plmn = _node(conn, "plmn", plmn_key, operator, {"mcc": mcc, "mnc": mnc, "country": country})
        svc = service or (fqdn.split(".")[0] if fqdn else "unknown")
        service_node = _node(conn, "service", svc, svc)
        fqdn_node = _node(conn, "fqdn", fqdn, fqdn, {"record_type": record_type})
        _edge(conn, plmn, "provides", service_node)
        _edge(conn, service_node, "publishes", fqdn_node, {"record_type": record_type})
        _edge(conn, plmn, "owns", fqdn_node)
        ips = [ip.strip() for ip in (resolved or "").split(",") if ip.strip()]
        for ip in ips:
            ip_node = _node(conn, "ip", ip, ip)
            _edge(conn, fqdn_node, "resolves_to", ip_node)
            if _table_exists(conn, "ip_enrichment"):
                enrich = conn.execute(
                    """SELECT asn,asn_org,hosting_provider FROM ip_enrichment
                       WHERE fqdn=? AND record_type=? AND ip=?""", (fqdn, record_type, ip)
                ).fetchone()
                if enrich:
                    asn, asn_org, provider = enrich
                    if asn:
                        asn_node = _node(conn, "asn", str(asn), asn_org or str(asn))
                        _edge(conn, ip_node, "announced_by", asn_node)
                        if provider:
                            provider_node = _node(conn, "provider", provider, provider)
                            _edge(conn, asn_node, "hosted_by", provider_node)

    if _table_exists(conn, "naptr_records"):
        for base, replacement in conn.execute(
            "SELECT base_fqdn,replacement FROM naptr_records WHERE replacement IS NOT NULL AND replacement != ''"
        ):
            source = _node(conn, "fqdn", base, base)
            target = _node(conn, "target", replacement.rstrip("."), replacement.rstrip("."))
            _edge(conn, source, "naptr_replacement", target)
    if _table_exists(conn, "srv_records"):
        for source_name, target in conn.execute(
            "SELECT COALESCE(source_fqdn,query_name),target FROM srv_records WHERE target IS NOT NULL AND target != ''"
        ):
            source = _node(conn, "fqdn", source_name, source_name)
            target = _node(conn, "target", target.rstrip("."), target.rstrip("."))
            _edge(conn, source, "srv_target", target)
    if _table_exists(conn, "fiveg_fqdns"):
        for fqdn, mcc, mnc, nf_type, source in conn.execute(
            "SELECT fqdn,mcc,mnc,nf_type,dns_source FROM fiveg_fqdns"
        ):
            plmn = _node(conn, "plmn", f"mcc{int(mcc):03d}-mnc{int(mnc):03d}")
            service = _node(conn, "service", nf_type or "5g-nf", nf_type or "5g-nf")
            fqdn_node = _node(conn, "fqdn", fqdn, fqdn, {"dns_source": source or "public"})
            _edge(conn, plmn, "provides", service)
            _edge(conn, service, "publishes", fqdn_node, {"dns_source": source or "public"})
    conn.commit()
    return graph_summary(conn)


def graph_summary(conn: sqlite3.Connection) -> dict[str, int]:
    init_graph(conn)
    result = {"nodes": conn.execute("SELECT COUNT(*) FROM graph_nodes WHERE active=1").fetchone()[0],
              "edges": conn.execute("SELECT COUNT(*) FROM graph_edges WHERE active=1").fetchone()[0]}
    for key, table, column in (("node_types", "graph_nodes", "node_type"), ("relationships", "graph_edges", "relationship")):
        result[key] = {r[0]: r[1] for r in conn.execute(f"SELECT {column},COUNT(*) FROM {table} WHERE active=1 GROUP BY {column}")}
    return result


def graph_rows(conn: sqlite3.Connection, relationship: str | None = None,
               node_type: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
    clauses = ["e.active=1", "s.active=1", "t.active=1"]
    params: list[Any] = []
    if relationship:
        clauses.append("e.relationship=?")
        params.append(relationship)
    if node_type:
        clauses.append("(s.node_type=? OR t.node_type=?)")
        params.extend([node_type, node_type])
    params.append(limit)
    rows = conn.execute(f"""SELECT s.node_type source_type,s.node_key source,e.relationship,
        t.node_type target_type,t.node_key target,e.metadata FROM graph_edges e
        JOIN graph_nodes s ON s.id=e.source_id JOIN graph_nodes t ON t.id=e.target_id
        WHERE {' AND '.join(clauses)} ORDER BY s.node_key,e.relationship,t.node_key LIMIT ?""", params)
    return [dict(row) for row in rows]


def export_graph(conn: sqlite3.Connection, fmt: str = "json", **filters: Any) -> str:
    rows = graph_rows(conn, **filters)
    if fmt == "json":
        nodes = [dict(r) for r in conn.execute("SELECT node_type,node_key,label,metadata FROM graph_nodes WHERE active=1 ORDER BY node_type,node_key")]
        return json.dumps({"nodes": nodes, "edges": rows}, indent=2)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["source_type", "source", "relationship", "target_type", "target", "metadata"], delimiter="\t" if fmt == "tsv" else ",")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()
