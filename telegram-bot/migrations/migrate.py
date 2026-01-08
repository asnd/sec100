#!/usr/bin/env python3
"""
Migration runner for the 3GPP Telegram Bot database.

Usage:
    python migrate.py [db_path] [mcc_mnc_json_path]

If no paths are provided, defaults to:
    - DB: ../go-3gpp-scanner/bin/database.db
    - JSON: ../epdg/mcc-mnc-list.json
"""

import sys
from pathlib import Path


def main():
    script_dir = Path(__file__).parent.parent.parent
    default_db_path = script_dir / "go-3gpp-scanner" / "bin" / "database.db"
    default_json_path = script_dir / "epdg" / "mcc-mnc-list.json"

    db_path = sys.argv[1] if len(sys.argv) > 1 else str(default_db_path)
    json_path = sys.argv[2] if len(sys.argv) > 2 else str(default_json_path)

    print("=" * 60)
    print("3GPP Telegram Bot - Database Migration Runner")
    print("=" * 60)
    print()

    # Import and run migration 001
    # Use importlib to import migration files with numeric prefixes
    import importlib.util
    migration_file = Path(__file__).parent / "001_add_countries.py"

    spec = importlib.util.spec_from_file_location("migration_001", migration_file)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    success = migration.run_migration(db_path, json_path)

    print()
    print("=" * 60)
    if success:
        print("✓ All migrations completed successfully")
    else:
        print("✗ Migration failed")
    print("=" * 60)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
