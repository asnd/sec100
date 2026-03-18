#!/usr/bin/env python3
"""
3GPP Public Domain Explorer — CLI

Query the scan database from the terminal.

Commands
--------
  stats                         Overview: totals, services, top countries
  countries  [--top N]          FQDNs and operator counts per country
  services                      Global service breakdown
  operator   --mcc M --mnc N    Detailed view of one operator
  search     <term>             Search operators by name (substring, case-insensitive)
  score      [--top N]          Capability score leaderboard
               [--country C]    … filtered to a country
               [--min-score N]  … filtered by minimum score
  export     [--format csv|json|tsv]
               [--output FILE]  Export all discovered FQDNs

Global flags
------------
  --db FILE     Path to database.db  (default: ./database.db)
  --no-color    Disable Rich colour output
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from db_queries import open_db, query_fqdns, query_operators, compute_scores, summary_stats
from subdomains import SCORE_WEIGHTS, SUBDOMAIN_DEFS

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

_console: "Console | None" = None


def get_console(no_color: bool = False) -> "Console":
    global _console
    if _console is None:
        _console = Console(no_color=no_color) if HAS_RICH else None
    return _console


# ── Formatting helpers ─────────────────────────────────────────────────────────

def print_rich_table(headers: list[str], rows: list[list], title: str = "",
                     col_styles: list[str] | None = None, no_color: bool = False) -> None:
    c = get_console(no_color)
    if HAS_RICH and c:
        t = Table(title=title, box=box.SIMPLE_HEAD, header_style="bold cyan",
                  show_lines=False, pad_edge=True)
        for i, h in enumerate(headers):
            style = (col_styles[i] if col_styles and i < len(col_styles) else "")
            t.add_column(h, style=style)
        for row in rows:
            t.add_row(*[str(v) for v in row])
        c.print(t)
    else:
        # Plain-text fallback
        if title:
            print(f"\n{'─' * 60}")
            print(f"  {title}")
            print(f"{'─' * 60}")
        widths = [
            max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
            for i, h in enumerate(headers)
        ]
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print("  ".join("─" * w for w in widths))
        for row in rows:
            print(fmt.format(*[str(v) for v in row]))


def print_panel(text: str, title: str = "", no_color: bool = False) -> None:
    c = get_console(no_color)
    if HAS_RICH and c:
        c.print(Panel(text, title=title, border_style="cyan"))
    else:
        if title:
            print(f"\n── {title} ──")
        print(text)


# ── Command implementations ────────────────────────────────────────────────────

def cmd_stats(args) -> int:
    conn = open_db(args.db)
    s = summary_stats(conn)
    conn.close()

    print_panel(
        f"[bold]Total FQDNs  :[/bold] {s['total_fqdns']:,}\n"
        f"[bold]Countries    :[/bold] {s['countries']}\n"
        f"[bold]Operators    :[/bold] {s['operators']}\n"
        f"[bold]Last scan    :[/bold] {s['last_scan'] or 'n/a'}",
        title="📡 3GPP Public Domain Explorer — Database Stats",
        no_color=args.no_color,
    )

    print_rich_table(
        ["Service", "Operators", "FQDNs"],
        [[r["service"], r["operators"], r["fqdns"]] for r in s["services"]],
        title="Service Breakdown",
        col_styles=["cyan", "green", "yellow"],
        no_color=args.no_color,
    )

    print_rich_table(
        ["Country", "Operators", "FQDNs"],
        [[r["country_name"], r["operators"], r["fqdns"]] for r in s["top_countries"]],
        title="Top 20 Countries",
        col_styles=["cyan", "green", "yellow"],
        no_color=args.no_color,
    )
    return 0


def cmd_countries(args) -> int:
    conn = open_db(args.db)
    df = query_fqdns(conn)
    conn.close()
    if df.empty:
        print("No data found.")
        return 0

    ct = (
        df.groupby("country_name")
        .agg(
            operators=("mcc", lambda x: df.loc[x.index, ["mnc", "mcc"]].drop_duplicates().shape[0]),
            fqdns=("fqdn", "count"),
            services=("service", lambda x: ", ".join(sorted(x.unique()))),
        )
        .reset_index()
        .sort_values("fqdns", ascending=False)
        .head(args.top)
    )

    print_rich_table(
        ["Country", "Operators", "FQDNs", "Services"],
        ct[["country_name", "operators", "fqdns", "services"]].values.tolist(),
        title=f"Top {args.top} Countries by Discovered FQDNs",
        no_color=args.no_color,
    )
    return 0


def cmd_country(args) -> int:
    """Per-service domain stats for one country (substring match)."""
    conn = open_db(args.db)
    df = query_fqdns(conn)
    conn.close()

    mask = df["country_name"].str.contains(args.name, case=False, na=False)
    df = df[mask]
    if df.empty:
        print(f"No records found for country matching '{args.name}'.")
        return 1

    matched = sorted(df["country_name"].unique())
    for country in matched:
        cdf = df[df["country_name"] == country]

        # Per-service counts
        svc_counts = (
            cdf.groupby("service")
            .agg(operators=("mcc", "nunique"), fqdns=("fqdn", "count"))
            .reset_index()
            .sort_values("fqdns", ascending=False)
        )

        # Operator list
        ops = (
            cdf.groupby(["mcc", "mnc", "operator"])
            .agg(fqdns=("fqdn", "count"), services=("service", lambda x: ", ".join(sorted(x.unique()))))
            .reset_index()
            .sort_values("fqdns", ascending=False)
        )

        total_ops = cdf[["mnc", "mcc"]].drop_duplicates().shape[0]
        print_panel(
            f"[bold]Country  :[/bold] {country}\n"
            f"[bold]Operators:[/bold] {total_ops}\n"
            f"[bold]FQDNs    :[/bold] {len(cdf)}",
            title=f"Country Stats — {country}",
            no_color=args.no_color,
        )
        print_rich_table(
            ["Service", "Operators", "FQDNs"],
            svc_counts[["service", "operators", "fqdns"]].values.tolist(),
            title="Services",
            col_styles=["cyan", "green", "yellow"],
            no_color=args.no_color,
        )
        if args.operators:
            print_rich_table(
                ["MCC", "MNC", "Operator", "FQDNs", "Services"],
                [
                    [r["mcc"], f"{r['mnc']:03d}", r["operator"], r["fqdns"], r["services"]]
                    for _, r in ops.iterrows()
                ],
                title="Operators",
                col_styles=["green", "green", "cyan", "yellow", ""],
                no_color=args.no_color,
            )
    return 0


def cmd_services(args) -> int:
    conn = open_db(args.db)
    df = query_fqdns(conn)
    conn.close()
    if df.empty:
        print("No data found.")
        return 0

    svc = (
        df.groupby("service")
        .agg(operators=("mcc", "nunique"), fqdns=("fqdn", "count"))
        .reset_index()
        .sort_values("fqdns", ascending=False)
    )
    # Enrich with metadata from SUBDOMAIN_DEFS
    meta = {d["subdomain"]: (d["category"], d["label"]) for d in SUBDOMAIN_DEFS}
    svc["category"] = svc["service"].map(lambda s: meta.get(s, ("", ""))[0])
    svc["description"] = svc["service"].map(lambda s: meta.get(s, ("", s))[1])

    print_rich_table(
        ["Service", "Category", "Description", "Operators", "FQDNs"],
        svc[["service", "category", "description", "operators", "fqdns"]].values.tolist(),
        title="Global Service Breakdown",
        col_styles=["cyan", "blue", "", "green", "yellow"],
        no_color=args.no_color,
    )
    return 0


def cmd_operator(args) -> int:
    conn = open_db(args.db)
    df = query_fqdns(conn, record_types=["A", "AAAA"])
    conn.close()

    rows = df[(df["mcc"] == args.mcc) & (df["mnc"] == args.mnc)]
    if rows.empty:
        print(f"No records found for MCC={args.mcc} MNC={args.mnc:03d}.")
        return 1

    info = rows.iloc[0]
    print_panel(
        f"[bold]Operator   :[/bold] {info['operator']}\n"
        f"[bold]Country    :[/bold] {info['country_name']}\n"
        f"[bold]MCC / MNC  :[/bold] {args.mcc} / {args.mnc:03d}\n"
        f"[bold]FQDNs found:[/bold] {len(rows)}",
        title=f"Operator Detail — {info['operator']}",
        no_color=args.no_color,
    )
    print_rich_table(
        ["Service", "FQDN", "Type", "Resolved IPs"],
        rows[["service", "fqdn", "record_type", "resolved_ips"]].values.tolist(),
        col_styles=["cyan", "", "green", "yellow"],
        no_color=args.no_color,
    )
    return 0


def cmd_search(args) -> int:
    conn = open_db(args.db)
    df = query_fqdns(conn, operator=args.term)
    conn.close()
    if df.empty:
        print(f"No operators matching '{args.term}'.")
        return 0

    found = (
        df.groupby(["mcc", "mnc", "operator", "country_name"])
        .agg(fqdns=("fqdn", "count"), services=("service", lambda x: ", ".join(sorted(x.unique()))))
        .reset_index()
        .sort_values(["country_name", "operator"])
    )
    print_rich_table(
        ["MCC", "MNC", "Operator", "Country", "FQDNs", "Services"],
        [
            [r["mcc"], f"{r['mnc']:03d}", r["operator"], r["country_name"], r["fqdns"], r["services"]]
            for _, r in found.iterrows()
        ],
        title=f"Search results for '{args.term}'",
        col_styles=["green", "green", "cyan", "", "yellow", ""],
        no_color=args.no_color,
    )
    return 0


def cmd_score(args) -> int:
    conn = open_db(args.db)
    df = query_fqdns(conn)
    scores = compute_scores(conn, df)
    conn.close()

    if scores.empty:
        print("No data to score.")
        return 0

    if args.country:
        scores = scores[scores["country_name"].str.contains(args.country, case=False, na=False)]
    if args.min_score:
        scores = scores[scores["score"] >= args.min_score]

    top = scores.head(args.top)

    # Score guide legend
    legend = "\n".join(
        f"  {icon} {label:<28} +{pts} pts"
        for svc, (label, pts, icon) in SCORE_WEIGHTS.items()
    ) + "\n  🚀 5G SA (NRF/SEPP)               +20 pts"
    print_panel(legend, title="Scoring guide  (max 120 pts)", no_color=args.no_color)

    print_rich_table(
        ["#", "Country", "Operator", "MCC", "MNC", "Score", "Services"],
        [
            [r["rank"], r["country_name"], r["operator"],
             r["mcc"], f"{r['mnc']:03d}", r["score"], r["capabilities"]]
            for _, r in top.iterrows()
        ],
        title=f"Capability Score Leaderboard — Top {args.top}",
        col_styles=["", "", "cyan", "green", "green", "bold yellow", ""],
        no_color=args.no_color,
    )
    return 0


def cmd_export(args) -> int:
    conn = open_db(args.db)
    df = query_fqdns(conn)
    conn.close()

    if df.empty:
        print("No data to export.")
        return 0

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout

    try:
        if args.format == "json":
            json.dump(df.to_dict(orient="records"), out, indent=2, default=str)
            out.write("\n")
        elif args.format == "tsv":
            df.to_csv(out, sep="\t", index=False)
        else:  # csv (default)
            df.to_csv(out, index=False)
    finally:
        if args.output:
            out.close()
            print(f"Exported {len(df)} records to {args.output}")
    return 0


# ── Argument parser ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="3gpppub-cli",
        description="Query the 3GPP Public Domain scan database from the terminal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--db",       default=os.environ.get("DB_PATH", "database.db"),
                   metavar="FILE", help="Path to database.db (default: database.db or $DB_PATH)")
    p.add_argument("--no-color", action="store_true", help="Disable colour output")

    sub = p.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # stats
    sub.add_parser("stats", help="Database overview: totals, services, top countries")

    # countries
    sc = sub.add_parser("countries", help="FQDNs per country")
    sc.add_argument("--top", type=int, default=30, metavar="N")

    # country (drill-down)
    sct = sub.add_parser("country", help="Per-service domain stats for a specific country")
    sct.add_argument("name", help="Country name (substring, case-insensitive)")
    sct.add_argument("--operators", action="store_true", help="Also list individual operators")

    # services
    sub.add_parser("services", help="Global service breakdown")

    # operator
    so = sub.add_parser("operator", help="Detail view for one operator")
    so.add_argument("--mcc", type=int, required=True)
    so.add_argument("--mnc", type=int, required=True)

    # search
    ss = sub.add_parser("search", help="Search operators by name substring")
    ss.add_argument("term", help="Search term (case-insensitive substring)")

    # score
    sk = sub.add_parser("score", help="Capability score leaderboard")
    sk.add_argument("--top",       type=int, default=20, metavar="N")
    sk.add_argument("--country",   default="",           metavar="NAME")
    sk.add_argument("--min-score", type=int, default=0,  metavar="N", dest="min_score")

    # export
    ex = sub.add_parser("export", help="Export all FQDNs to CSV / JSON / TSV")
    ex.add_argument("--format", choices=["csv", "json", "tsv"], default="csv")
    ex.add_argument("--output", metavar="FILE", help="Output file (default: stdout)")

    return p


COMMANDS = {
    "stats":     cmd_stats,
    "countries": cmd_countries,
    "country":   cmd_country,
    "services":  cmd_services,
    "operator":  cmd_operator,
    "search":    cmd_search,
    "score":     cmd_score,
    "export":    cmd_export,
}


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return COMMANDS[args.command](args)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
