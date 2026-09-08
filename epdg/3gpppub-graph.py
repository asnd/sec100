#!/usr/bin/env python3
"""Build and export the PLMN-to-infrastructure relationship graph."""

import argparse
import sqlite3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from graph import build_graph, export_graph, graph_rows, graph_summary, init_graph


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="database.db", help="SQLite database path")
    parser.add_argument("--format", choices=("json", "csv", "tsv"), default="json")
    parser.add_argument("--output", help="Output file (default: stdout)")
    parser.add_argument("--relationship", help="Only export this relationship")
    parser.add_argument("--node-type", help="Only export edges touching this node type")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--no-rebuild", action="store_true", help="Export the existing materialized graph")
    parser.add_argument("--summary", action="store_true", help="Print graph counts")
    args = parser.parse_args()
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    init_graph(conn)
    summary = graph_summary(conn) if args.no_rebuild else build_graph(conn)
    if args.summary:
        print(summary)
    content = export_graph(conn, args.format, relationship=args.relationship, node_type=args.node_type, limit=args.limit)
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content)
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
