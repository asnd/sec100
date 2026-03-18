"""
Shared database query and scoring logic.

Used by both 3gpppub-cli.py (terminal) and stream-oplookup.py (Streamlit).
Neither UI framework is imported here — pure sqlite3 + pandas.
"""

import sqlite3
from pathlib import Path

import pandas as pd

from subdomains import SCORE_WEIGHTS, sql_case_when

DEFAULT_DB = Path(__file__).parent / "database.db"


def open_db(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else DEFAULT_DB
    if path.is_dir():
        raise FileNotFoundError(
            f"{path} is a directory — the database file does not exist on the host.\n"
            "Docker created an empty directory at the mount point.\n"
            "Run 3gpppub-dns-database-population.py first, then re-mount the file:\n"
            "  docker run --rm -v $(pwd)/epdg/database.db:/data/database.db 3gpp-explorer stats"
        )
    if not path.is_file():
        raise FileNotFoundError(
            f"Database not found: {path}\n"
            "Run 3gpppub-dns-database-population.py first."
        )
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def query_fqdns(
    conn: sqlite3.Connection,
    countries: list[str] | None = None,
    services: list[str] | None = None,
    record_types: list[str] | None = None,
    operator: str | None = None,
) -> pd.DataFrame:
    df = pd.read_sql_query(
        f"""
        SELECT f.mnc, f.mcc, f.operator, COALESCE(f.country_name, 'Unknown') AS country_name,
               f.fqdn, f.record_type, f.resolved_ips,
               f.first_seen, f.last_seen,
               COALESCE(f.service, ({sql_case_when('f.fqdn')})) AS service
        FROM available_fqdns f
        ORDER BY f.country_name, f.operator
        """,
        conn,
    )
    if countries:
        df = df[df["country_name"].isin(countries)]
    if services:
        df = df[df["service"].isin(services)]
    if record_types:
        df = df[df["record_type"].isin(record_types)]
    if operator:
        df = df[df["operator"].str.contains(operator, case=False, na=False)]
    return df


def query_operators(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT mnc, mcc, operator, country_name, country_code, last_scanned "
        "FROM operators ORDER BY country_name",
        conn,
    )


def compute_scores(conn: sqlite3.Connection, df: pd.DataFrame) -> pd.DataFrame:
    """Return per-operator capability scores, sorted descending."""
    if df.empty:
        return pd.DataFrame()

    score_pivot = (
        df.groupby(["mnc", "mcc", "operator", "country_name", "service"])
        .size()
        .reset_index(name="count")
        .pivot_table(
            index=["mnc", "mcc", "operator", "country_name"],
            columns="service",
            values="count",
            fill_value=0,
        )
        .reset_index()
    )

    # 5G SA bonus — check for NRF/SEPP table populated by 3gpppub-5g-discovery.py
    has_5g = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='fiveg_fqdns'"
    ).fetchone()
    if has_5g:
        fiveg_keys = {
            r[0] for r in conn.execute(
                "SELECT DISTINCT mcc || '-' || mnc FROM fiveg_fqdns"
            ).fetchall()
        }
        score_pivot["_5g_key"] = (
            score_pivot["mcc"].astype(str) + "-" + score_pivot["mnc"].astype(str)
        )
        score_pivot["5g_sa"] = score_pivot["_5g_key"].isin(fiveg_keys).astype(int)
    else:
        score_pivot["5g_sa"] = 0

    def _score_row(row) -> tuple[int, str]:
        pts = 0
        caps = []
        for svc, (label, weight, icon) in SCORE_WEIGHTS.items():
            if svc in row and row[svc] > 0:
                pts += weight
                caps.append(f"{icon} {label} +{weight}")
        if row.get("5g_sa", 0):
            pts += 20
            caps.append("🚀 5G SA +20")
        return pts, " | ".join(caps)

    score_pivot[["score", "capabilities"]] = score_pivot.apply(
        lambda r: pd.Series(_score_row(r)), axis=1
    )
    score_pivot = score_pivot.sort_values("score", ascending=False).reset_index(drop=True)
    score_pivot.insert(0, "rank", score_pivot.index + 1)
    return score_pivot


def summary_stats(conn: sqlite3.Connection) -> dict:
    """Return a dict of high-level database statistics."""
    totals = conn.execute(
        """
        SELECT
          COUNT(*)                        AS total_fqdns,
          COUNT(DISTINCT country_name)    AS countries,
          COUNT(DISTINCT mcc || '-' || mnc) AS operators
        FROM available_fqdns
        """
    ).fetchone()
    svc_rows = conn.execute(
        """
        SELECT COALESCE(service,'other') AS service,
               COUNT(DISTINCT mcc||'-'||mnc) AS operators,
               COUNT(*) AS fqdns
        FROM available_fqdns
        GROUP BY service
        ORDER BY fqdns DESC
        """
    ).fetchall()
    top_countries = conn.execute(
        """
        SELECT country_name,
               COUNT(DISTINCT mcc||'-'||mnc) AS operators,
               COUNT(*) AS fqdns
        FROM available_fqdns
        GROUP BY country_name
        ORDER BY fqdns DESC
        LIMIT 20
        """
    ).fetchall()
    last_scan = conn.execute(
        "SELECT MAX(last_scanned) FROM operators"
    ).fetchone()[0]
    return {
        "total_fqdns":    totals["total_fqdns"],
        "countries":      totals["countries"],
        "operators":      totals["operators"],
        "services":       [dict(r) for r in svc_rows],
        "top_countries":  [dict(r) for r in top_countries],
        "last_scan":      last_scan,
    }
