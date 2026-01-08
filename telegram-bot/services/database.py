"""
Database service for 3GPP Telegram Bot.

Provides async database queries for operators, countries, and FQDNs.
Uses aiosqlite for non-blocking database operations.
"""

import aiosqlite
from typing import List, Dict, Tuple, Optional
import os
from pathlib import Path


class Database:
    """Async database wrapper for 3GPP network queries."""

    def __init__(self, db_path: str):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Database not found: {db_path}")

    async def get_operators_by_country(
        self,
        country_name: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict]:
        """
        Get operators for a given country name.

        Args:
            country_name: Country name (case-insensitive, supports partial match)
            limit: Maximum number of results
            offset: Offset for pagination

        Returns:
            List of dicts with keys: operator, mnc, mcc
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT DISTINCT o.operator, o.mnc, o.mcc
                FROM countries c
                JOIN operators o ON CAST(c.mcc AS INTEGER) = o.mcc
                WHERE LOWER(c.country_name) LIKE LOWER(?)
                ORDER BY o.operator, o.mnc
                LIMIT ? OFFSET ?
            """, (f"%{country_name}%", limit, offset))

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_countries_by_name(
        self,
        country_name: str,
        limit: int = 10
    ) -> List[Dict]:
        """
        Search for countries by name (fuzzy match).

        Args:
            country_name: Country name (partial match supported)
            limit: Maximum number of results

        Returns:
            List of dicts with keys: country_name, country_code, mcc
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT DISTINCT country_name, country_code, mcc
                FROM countries
                WHERE LOWER(country_name) LIKE LOWER(?)
                ORDER BY country_name, mcc
                LIMIT ?
            """, (f"%{country_name}%", limit))

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_operators_by_mcc(
        self,
        mcc: int,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict]:
        """
        Get operators for a given MCC code.

        Args:
            mcc: Mobile Country Code
            limit: Maximum number of results
            offset: Offset for pagination

        Returns:
            List of dicts with keys: operator, mnc, mcc
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT DISTINCT operator, mnc, mcc
                FROM operators
                WHERE mcc = ?
                ORDER BY operator, mnc
                LIMIT ? OFFSET ?
            """, (mcc, limit, offset))

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_operators_by_mnc_mcc(
        self,
        mnc: int,
        mcc: int
    ) -> List[Dict]:
        """
        Get operators for a given MNC-MCC pair.

        Args:
            mnc: Mobile Network Code
            mcc: Mobile Country Code

        Returns:
            List of dicts with keys: operator, mnc, mcc
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT DISTINCT operator, mnc, mcc
                FROM operators
                WHERE mnc = ? AND mcc = ?
                ORDER BY operator
            """, (mnc, mcc))

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_operators_by_name(
        self,
        operator_name: str,
        exact: bool = False
    ) -> List[Dict]:
        """
        Search for operators by name.

        Args:
            operator_name: Operator name
            exact: If True, exact match; if False, fuzzy match

        Returns:
            List of dicts with keys: operator, mnc, mcc
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            if exact:
                cursor = await db.execute("""
                    SELECT DISTINCT operator, mnc, mcc
                    FROM operators
                    WHERE operator = ?
                    ORDER BY mnc
                """, (operator_name,))
            else:
                cursor = await db.execute("""
                    SELECT DISTINCT operator, mnc, mcc
                    FROM operators
                    WHERE LOWER(operator) LIKE LOWER(?)
                    ORDER BY operator, mnc
                    LIMIT 20
                """, (f"%{operator_name}%",))

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_fqdns_by_operator(
        self,
        operator_name: str
    ) -> List[str]:
        """
        Get all FQDNs for a given operator.

        Args:
            operator_name: Exact operator name

        Returns:
            List of FQDN strings
        """
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                SELECT fqdn
                FROM available_fqdns
                WHERE operator = ?
                ORDER BY fqdn
            """, (operator_name,))

            rows = await cursor.fetchall()
            return [row[0] for row in rows]

    async def get_mnc_mcc_pairs_by_operator(
        self,
        operator_name: str
    ) -> List[Tuple[int, int]]:
        """
        Get all MNC-MCC pairs for a given operator.

        Args:
            operator_name: Exact operator name

        Returns:
            List of (mnc, mcc) tuples
        """
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                SELECT DISTINCT mnc, mcc
                FROM operators
                WHERE operator = ?
                ORDER BY mnc, mcc
            """, (operator_name,))

            rows = await cursor.fetchall()
            return [(row[0], row[1]) for row in rows]

    async def get_mccs_by_phone_code(
        self,
        phone_code: str
    ) -> List[Dict]:
        """
        Get MCC codes for a given phone country code (E.164).

        Args:
            phone_code: E.164 country code (e.g., "43", "1")

        Returns:
            List of dicts with keys: country_code, country_name, mcc
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT p.country_code, p.country_name, c.mcc
                FROM phone_country_codes p
                JOIN countries c ON p.country_code = c.country_code
                WHERE p.phone_code = ?
                ORDER BY p.country_name, c.mcc
            """, (phone_code,))

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def log_query(
        self,
        telegram_user_id: int,
        query_type: str,
        query_value: str,
        result_count: int
    ) -> None:
        """
        Log a query to the database for analytics.

        Args:
            telegram_user_id: Telegram user ID
            query_type: Type of query (country, mcc, mnc, msisdn, operator)
            query_value: Query value (e.g., "Austria", "232")
            result_count: Number of results returned
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO query_log (telegram_user_id, query_type, query_value, result_count)
                VALUES (?, ?, ?, ?)
            """, (telegram_user_id, query_type, query_value, result_count))
            await db.commit()

    async def get_query_stats(
        self,
        user_id: Optional[int] = None,
        hours: int = 24
    ) -> Dict:
        """
        Get query statistics.

        Args:
            user_id: Optional user ID to filter by
            hours: Number of hours to look back

        Returns:
            Dictionary with statistics
        """
        async with aiosqlite.connect(self.db_path) as db:
            # Total queries
            if user_id:
                cursor = await db.execute("""
                    SELECT COUNT(*) FROM query_log
                    WHERE telegram_user_id = ?
                    AND timestamp >= datetime('now', '-' || ? || ' hours')
                """, (user_id, hours))
            else:
                cursor = await db.execute("""
                    SELECT COUNT(*) FROM query_log
                    WHERE timestamp >= datetime('now', '-' || ? || ' hours')
                """, (hours,))

            total_queries = (await cursor.fetchone())[0]

            # Queries by type
            if user_id:
                cursor = await db.execute("""
                    SELECT query_type, COUNT(*) as count
                    FROM query_log
                    WHERE telegram_user_id = ?
                    AND timestamp >= datetime('now', '-' || ? || ' hours')
                    GROUP BY query_type
                    ORDER BY count DESC
                """, (user_id, hours))
            else:
                cursor = await db.execute("""
                    SELECT query_type, COUNT(*) as count
                    FROM query_log
                    WHERE timestamp >= datetime('now', '-' || ? || ' hours')
                    GROUP BY query_type
                    ORDER BY count DESC
                """, (hours,))

            query_types = dict(await cursor.fetchall())

            return {
                "total_queries": total_queries,
                "by_type": query_types,
                "hours": hours
            }


def get_default_db_path() -> str:
    """
    Get the default database path by searching common locations.

    Returns:
        Path to database file

    Raises:
        FileNotFoundError: If database is not found
    """
    script_dir = Path(__file__).parent.parent.parent

    search_paths = [
        script_dir / "go-3gpp-scanner" / "bin" / "database.db",
        script_dir / "database.db",
        script_dir / "epdg" / "database.db",
    ]

    for path in search_paths:
        if path.exists():
            return str(path)

    raise FileNotFoundError(
        f"Database not found. Searched paths: {[str(p) for p in search_paths]}"
    )
