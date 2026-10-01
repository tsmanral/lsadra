"""Fixtures for the storage contract suite.

Every test gets a fresh SQLite file under ``tmp_path`` whose schema is built by
``init_db()`` running the real migrations in ``lsadra/storage/migrations/`` —
never a hand-rolled schema, so the suite breaks when the migrations drift.

``database.py`` binds ``DB_PATH`` at import time (``from lsadra.config import
DB_PATH``), so both ``lsadra.config.DB_PATH`` and
``lsadra.storage.database.DB_PATH`` are patched. ``monkeypatch`` restores both
after each test, so nothing leaks into other test modules and the real
``data/`` directory is never touched.
"""

import gc
import sqlite3
from typing import Any, Dict, List

import pytest

import lsadra.config as config
import lsadra.storage.database as database
from tests.storage._support import DEVICE_ID, USER_ID, USERNAME


@pytest.fixture
def db(tmp_path, monkeypatch):
    """The storage module, pointed at a fresh migrated temp database."""
    path = tmp_path / "storage_contract.db"
    monkeypatch.setattr(config, "DB_PATH", path)
    monkeypatch.setattr(database, "DB_PATH", path)
    database.init_db()
    yield database
    # Storage functions close their own connection even when a statement raises
    # (pinned by test_connection_lifecycle.py). Connections opened directly by a
    # test (e.g. a lock probe) may still be unreferenced-but-open; collect them
    # so later tests start clean.
    gc.collect()


@pytest.fixture
def sql(db):
    """Run raw SQL against the test DB (test setup / inspection only)."""

    def run(statement: str, params: tuple = ()) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(str(db.DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            rows = [dict(r) for r in conn.execute(statement, params).fetchall()]
            conn.commit()
            return rows
        finally:
            conn.close()

    return run


@pytest.fixture
def traced(db, monkeypatch):
    """Record every connection the storage module opens and the SQL it runs.

    Returns a list with one entry per opened connection: the statements SQLite
    executed on it (implicit ``BEGIN`` / ``COMMIT`` / ``ROLLBACK`` included).
    Request it after ``seeded`` so fixture setup is not recorded.
    """
    connections: List[List[str]] = []
    real_get_connection = database.get_connection

    def tracing_get_connection():
        conn = real_get_connection()
        statements: List[str] = []
        conn.set_trace_callback(statements.append)
        connections.append(statements)
        return conn

    monkeypatch.setattr(database, "get_connection", tracing_get_connection)
    return connections


@pytest.fixture
def seeded(db):
    """One synthetic user owning one device (FKs require both for events)."""
    db.create_user(USER_ID, USERNAME, "synthetic-not-a-real-hash", "ANALYST")
    db.create_device(DEVICE_ID, USER_ID, "host-1", "linux", "synthetic-key-hash")
    return db
