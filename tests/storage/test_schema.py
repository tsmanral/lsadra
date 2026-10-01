"""Contract: connection model, schema bootstrap, and migration idempotency.

Covers: get_connection, init_db (plus migration_runner.run_migrations).
"""

import sqlite3

import lsadra.storage.database as database
from lsadra.storage.migration_runner import MIGRATIONS_DIR, run_migrations

EXPECTED_TABLES = {
    "_schema_migrations",
    "users",
    "devices",
    "registration_tokens",
    "normalized_events",
    "detection_watermarks",
    "anomalies",
    "incidents",
    "device_heartbeats",
    "model_registry",
    "metrics_5min",
    "threat_intel_cache",
    "ip_geolocation",
    "feature_drift",
    "alerts_feedback",
    "ingestion_stats",
}


def _schema(sql):
    return sql(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    )


# ── get_connection ─────────────────────────────────────────────────────────


def test_get_connection_returns_row_factory_wal_and_foreign_keys(db):
    conn = db.get_connection()
    try:
        assert isinstance(conn, sqlite3.Connection)
        assert conn.row_factory is sqlite3.Row
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()


def test_get_connection_sets_30s_busy_timeout(db):
    # Sprint 2 (S2-3): explicit 30 s, up from sqlite3's 5 s default.
    # test_concurrency.py sizes its contention load against db.BUSY_TIMEOUT_S.
    assert db.BUSY_TIMEOUT_S == 30
    conn = db.get_connection()
    try:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30_000
    finally:
        conn.close()


def test_get_connection_sets_synchronous_normal(db):
    conn = db.get_connection()
    try:
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
    finally:
        conn.close()


def test_init_db_sets_wal_once_and_it_persists_in_the_file(tmp_path, monkeypatch, db):
    fresh = tmp_path / "fresh_wal.db"
    monkeypatch.setattr(database, "DB_PATH", fresh)
    # The per-call path no longer issues journal_mode: a file that never went
    # through init_db() stays in SQLite's default rollback-journal mode.
    conn = db.get_connection()
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    finally:
        conn.close()
    db.init_db()
    # A bare connection (no LSADRA pragmas) sees WAL: it is stored in the file.
    raw = sqlite3.connect(str(fresh))
    try:
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    finally:
        raw.close()


def test_get_connection_issues_per_connection_pragmas_only(db, monkeypatch):
    statements, kwargs_seen = [], []
    real_connect = sqlite3.connect

    def traced_connect(*args, **kwargs):
        kwargs_seen.append(kwargs)
        conn = real_connect(*args, **kwargs)
        conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    db.get_connection().close()
    assert kwargs_seen == [{"timeout": 30}]
    pragmas = [s for s in statements if s.upper().startswith("PRAGMA")]
    assert pragmas == ["PRAGMA busy_timeout=30000", "PRAGMA synchronous=NORMAL", "PRAGMA foreign_keys=ON"]
    assert not any("journal_mode" in s for s in statements)


def test_get_connection_creates_missing_parent_directory(db, tmp_path, monkeypatch):
    nested = tmp_path / "a" / "b" / "nested.db"
    monkeypatch.setattr(database, "DB_PATH", nested)
    conn = db.get_connection()
    conn.close()
    assert nested.parent.is_dir()
    assert nested.exists()


def test_get_connection_returns_a_new_connection_per_call(db):
    first, second = db.get_connection(), db.get_connection()
    try:
        assert first is not second
    finally:
        first.close()
        second.close()


# ── init_db / migrations ───────────────────────────────────────────────────


def test_init_db_applies_every_migration_file_in_order(db, sql):
    files = sorted(p.name for p in MIGRATIONS_DIR.glob("*.sql"))
    applied = [r["filename"] for r in sql("SELECT filename FROM _schema_migrations ORDER BY id")]
    assert files, "no migrations discovered"
    assert applied == files


def test_init_db_creates_the_full_schema(db, sql):
    tables = {r["name"] for r in sql("SELECT name FROM sqlite_master WHERE type='table'")}
    assert EXPECTED_TABLES <= tables
    incident_cols = {r["name"] for r in sql("PRAGMA table_info(incidents)")}
    assert "playbook" in incident_cols  # added by 003_incident_playbooks.sql


def test_init_db_returns_none(db):
    assert db.init_db() is None


def test_init_db_is_idempotent(db, sql):
    before = _schema(sql)
    migrations_before = sql("SELECT filename, applied_at FROM _schema_migrations ORDER BY id")
    db.init_db()
    db.init_db()
    assert _schema(sql) == before
    assert (
        sql("SELECT filename, applied_at FROM _schema_migrations ORDER BY id") == migrations_before
    )


def test_run_migrations_reports_zero_when_up_to_date(db):
    conn = db.get_connection()
    try:
        assert run_migrations(conn) == 0
    finally:
        conn.close()


def test_run_migrations_on_empty_db_applies_all_files(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "fresh.db"))
    try:
        assert run_migrations(conn) == len(list(MIGRATIONS_DIR.glob("*.sql")))
        assert run_migrations(conn) == 0
    finally:
        conn.close()


def test_init_db_rerun_preserves_existing_rows(db):
    db.create_user("u-keep", "keeper", "synthetic-hash")
    db.init_db()
    assert db.get_user_by_id("u-keep") is not None
