"""
LSADRA V3 — Database migration runner.

Executes SQL migration files in order and tracks which have been applied.
Migrations are stored in ``lsadra/storage/migrations/`` and named
with a numeric prefix (e.g. ``001_initial_v3_schema.sql``).
"""

import logging
import sqlite3
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_MIGRATION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS _schema_migrations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    filename   TEXT UNIQUE NOT NULL,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


def _get_applied(conn: sqlite3.Connection) -> List[str]:
    """Return list of already-applied migration filenames."""
    try:
        rows = conn.execute("SELECT filename FROM _schema_migrations ORDER BY id").fetchall()
        return [r[0] for r in rows]
    except sqlite3.OperationalError:
        return []


def _discover_migrations() -> List[Path]:
    """Find all .sql files in the migrations directory, sorted by name."""
    if not MIGRATIONS_DIR.exists():
        logger.warning("Migrations directory not found: %s", MIGRATIONS_DIR)
        return []
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def run_migrations(conn: sqlite3.Connection) -> int:
    """
    Apply any pending SQL migrations.

    Args:
        conn: An open SQLite connection.

    Returns:
        Number of migrations applied in this run.
    """
    # Ensure migration tracking table exists
    conn.executescript(_MIGRATION_TABLE_SQL)

    applied = set(_get_applied(conn))
    pending = [m for m in _discover_migrations() if m.name not in applied]

    if not pending:
        logger.info("Database schema is up to date (no pending migrations).")
        return 0

    count = 0
    for migration_file in pending:
        logger.info("Applying migration: %s", migration_file.name)
        sql = migration_file.read_text(encoding="utf-8")
        try:
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO _schema_migrations (filename) VALUES (?)",
                (migration_file.name,),
            )
            conn.commit()
            count += 1
            logger.info("Migration applied successfully: %s", migration_file.name)
        except Exception:
            logger.exception("Migration FAILED: %s", migration_file.name)
            raise

    logger.info("Applied %d migration(s).", count)
    return count
