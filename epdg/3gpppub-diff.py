#!/usr/bin/env python3
"""
Feature 3: Scan Diff / Change Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Takes snapshots of the database state and compares them over time.
Surfaces:
  • New FQDNs    — operators that newly published a service
  • Removed FQDNs — services that disappeared (decommissioned / outage)
  • IP Changes   — same FQDN resolving to different IPs (migration, failover)
  • New countries — first operator in a country to publish a service

Snapshots are stored in the same SQLite database so history is preserved
across runs. Each scan of the database creates a lightweight snapshot entry.

Usage:
  # Save a snapshot of the current DB state (do this after each population run)
  python3 3gpppub-diff.py --snapshot

  # Compare latest snapshot to the previous one
  python3 3gpppub-diff.py --diff

  # Compare two specific snapshots by ID
  python3 3gpppub-diff.py --diff --from-snapshot 3 --to-snapshot 5

  # List all saved snapshots
  python3 3gpppub-diff.py --list
"""

import argparse
import json
import logging
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

SCHEMA_DIFF = """
CREATE TABLE IF NOT EXISTS snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    taken_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    label      TEXT,
    fqdn_count INTEGER,
    data       TEXT   -- JSON: list of {fqdn, record_type, resolved_ips, operator, country_name}
);

CREATE TABLE IF NOT EXISTS diff_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    from_snapshot  INTEGER,
    to_snapshot    INTEGER,
    event_type     TEXT NOT NULL,  -- 'added', 'removed', 'ip_changed', 'new_country'
    country_name   TEXT,
    operator       TEXT,
    fqdn           TEXT,
    record_type    TEXT,
    old_ips        TEXT,
    new_ips        TEXT,
    service        TEXT
);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    if not Path(db_path).exists():
        log.error("Database %s not found.", db_path)
        sys.exit(1)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_DIFF)
    conn.commit()
    return conn


def service_from_fqdn(fqdn: str) -> str:
    for svc in ("epdg.epc", "xcap.ims", "ims", "bsf", "gan"):
        if fqdn.startswith(svc):
            return svc
    return fqdn.split(".")[0]


def take_snapshot(conn: sqlite3.Connection, label: str | None = None) -> int:
    rows = conn.execute(
        """
        SELECT fqdn, record_type, resolved_ips, operator, country_name, mnc, mcc
        FROM available_fqdns
        ORDER BY fqdn, record_type
        """
    ).fetchall()
    data = [dict(r) for r in rows]
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO snapshots (taken_at, label, fqdn_count, data) VALUES (?, ?, ?, ?)",
        (now, label or now, len(data), json.dumps(data)),
    )
    conn.commit()
    snap_id = cur.lastrowid
    log.info("Snapshot #%d saved — %d FQDNs, label: %s", snap_id, len(data), label or now)
    return snap_id


def load_snapshot(conn: sqlite3.Connection, snap_id: int) -> tuple[dict, dict]:
    """Return (meta_row, dict keyed by (fqdn, record_type) → row)."""
    row = conn.execute("SELECT * FROM snapshots WHERE id = ?", (snap_id,)).fetchone()
    if not row:
        log.error("Snapshot #%d not found.", snap_id)
        sys.exit(1)
    data = json.loads(row["data"])
    index = {(r["fqdn"], r["record_type"]): r for r in data}
    return dict(row), index


def diff_snapshots(
    conn: sqlite3.Connection, from_id: int, to_id: int
) -> dict[str, list]:
    from_meta, from_idx = load_snapshot(conn, from_id)
    to_meta,   to_idx   = load_snapshot(conn, to_id)

    log.info(
        "Diffing snapshot #%d (%s, %d FQDNs) → #%d (%s, %d FQDNs)",
        from_id, from_meta["taken_at"], from_meta["fqdn_count"],
        to_id,   to_meta["taken_at"],   to_meta["fqdn_count"],
    )

    from_keys = set(from_idx.keys())
    to_keys   = set(to_idx.keys())

    events: dict[str, list] = {
        "added":       [],
        "removed":     [],
        "ip_changed":  [],
        "new_country": [],
    }

    from_countries = {from_idx[k]["country_name"] for k in from_keys}
    to_countries   = {to_idx[k]["country_name"]   for k in to_keys}

    # Added
    for key in sorted(to_keys - from_keys):
        row = to_idx[key]
        events["added"].append({
            "country_name": row["country_name"],
            "operator":     row["operator"],
            "fqdn":         row["fqdn"],
            "record_type":  row["record_type"],
            "new_ips":      row["resolved_ips"],
            "service":      service_from_fqdn(row["fqdn"]),
        })

    # Removed
    for key in sorted(from_keys - to_keys):
        row = from_idx[key]
        events["removed"].append({
            "country_name": row["country_name"],
            "operator":     row["operator"],
            "fqdn":         row["fqdn"],
            "record_type":  row["record_type"],
            "old_ips":      row["resolved_ips"],
            "service":      service_from_fqdn(row["fqdn"]),
        })

    # IP changes
    for key in from_keys & to_keys:
        old_ips = set((from_idx[key]["resolved_ips"] or "").split(","))
        new_ips = set((to_idx[key]["resolved_ips"]   or "").split(","))
        if old_ips != new_ips:
            row = to_idx[key]
            events["ip_changed"].append({
                "country_name": row["country_name"],
                "operator":     row["operator"],
                "fqdn":         row["fqdn"],
                "record_type":  row["record_type"],
                "old_ips":      from_idx[key]["resolved_ips"],
                "new_ips":      row["resolved_ips"],
                "service":      service_from_fqdn(row["fqdn"]),
            })

    # New countries (first operator in a country published a service)
    for country in sorted(to_countries - from_countries):
        events["new_country"].append({"country_name": country})

    # Persist events
    now = datetime.now(timezone.utc).isoformat()
    for etype, rows in events.items():
        for ev in rows:
            conn.execute(
                """
                INSERT INTO diff_events
                    (detected_at, from_snapshot, to_snapshot, event_type,
                     country_name, operator, fqdn, record_type, old_ips, new_ips, service)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now, from_id, to_id, etype,
                    ev.get("country_name"), ev.get("operator"),
                    ev.get("fqdn"), ev.get("record_type"),
                    ev.get("old_ips"), ev.get("new_ips"),
                    ev.get("service"),
                ),
            )
    conn.commit()
    return events


def print_diff(events: dict[str, list], from_id: int, to_id: int) -> None:
    added      = events["added"]
    removed    = events["removed"]
    ip_changed = events["ip_changed"]
    new_ctry   = events["new_country"]

    total = sum(len(v) for v in events.values())
    print(f"\n{'═'*70}")
    print(f"  Diff: snapshot #{from_id} → #{to_id}   ({total} total changes)")
    print(f"{'═'*70}")

    if new_ctry:
        print(f"\n🌍  New countries ({len(new_ctry)}):")
        for ev in new_ctry:
            print(f"     + {ev['country_name']}")

    if added:
        print(f"\n✅  New FQDNs added ({len(added)}):")
        for ev in added:
            print(f"     [{ev['service']:<10}] {ev['fqdn']:<65} {ev['country_name']}")

    if removed:
        print(f"\n❌  FQDNs removed ({len(removed)}):")
        for ev in removed:
            print(f"     [{ev['service']:<10}] {ev['fqdn']:<65} {ev['country_name']}")

    if ip_changed:
        print(f"\n🔄  IP changes ({len(ip_changed)}):")
        for ev in ip_changed:
            print(f"     {ev['fqdn']}")
            print(f"       was: {ev['old_ips']}")
            print(f"       now: {ev['new_ips']}")

    if total == 0:
        print("\n  No changes detected between the two snapshots.")


def list_snapshots(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        "SELECT id, taken_at, label, fqdn_count FROM snapshots ORDER BY id"
    ).fetchall()
    if not rows:
        print("No snapshots stored yet. Run with --snapshot first.")
        return
    print(f"\n{'ID':>4}  {'Taken at':<28}  {'FQDNs':>7}  Label")
    print("─" * 70)
    for row in rows:
        print(f"{row['id']:>4}  {row['taken_at']:<28}  {row['fqdn_count']:>7}  {row['label']}")


def main():
    parser = argparse.ArgumentParser(
        description="Snapshot and diff 3GPP DNS scan results over time."
    )
    parser.add_argument("--db", default="database.db")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--snapshot", action="store_true",
                       help="Save a snapshot of the current DB state")
    group.add_argument("--diff", action="store_true",
                       help="Compare two snapshots (default: latest vs previous)")
    group.add_argument("--list", action="store_true",
                       help="List all stored snapshots")

    parser.add_argument("--label", help="Label for the snapshot (used with --snapshot)")
    parser.add_argument("--from-snapshot", type=int, metavar="ID",
                        help="Snapshot ID to diff from")
    parser.add_argument("--to-snapshot", type=int, metavar="ID",
                        help="Snapshot ID to diff to (default: latest)")
    args = parser.parse_args()

    conn = init_db(args.db)

    if args.list:
        list_snapshots(conn)

    elif args.snapshot:
        take_snapshot(conn, label=args.label)

    elif args.diff:
        snap_ids = [r["id"] for r in conn.execute(
            "SELECT id FROM snapshots ORDER BY id DESC LIMIT 2"
        ).fetchall()]

        if len(snap_ids) < 2 and not (args.from_snapshot and args.to_snapshot):
            log.error("Need at least 2 snapshots to diff. Run --snapshot twice.")
            sys.exit(1)

        to_id   = args.to_snapshot   or snap_ids[0]
        from_id = args.from_snapshot or snap_ids[1]
        events  = diff_snapshots(conn, from_id, to_id)
        print_diff(events, from_id, to_id)

    conn.close()


if __name__ == "__main__":
    main()
