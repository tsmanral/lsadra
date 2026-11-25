"""
G-27 — Data at rest: file permissions, full retention, backup and restore.

Attacker story: the SQLite database (raw log lines, accounts, device key
hashes) was created world-readable by default; deleted rows lingered in free
pages; incidents, analyst feedback, IP lookups and registration tokens were
kept forever; and there was no tested way to back up and restore.

Secure behavior pinned here: start-up restricts the data directory to 0700 /
0600; secure_delete is on; retention also expires closed incidents, feedback,
threat-intel and geolocation rows and old registration tokens (open incidents
stay); audit rows outlive normal retention; a backup carries a SHA-256
manifest, a tampered backup is refused, and restore round-trips the data.
SYNTHETIC data only.
"""

import os
import stat
from datetime import datetime, timedelta

import pytest

from lsadra import backup
from lsadra.security import audit
from lsadra.security.filesystem import restrict_data_dir
from lsadra.storage import database as db
from tests.security._identity_support import identity_env, make_user  # noqa: F401 — fixture

OLD = (datetime.utcnow() - timedelta(days=400)).isoformat()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_data_dir_is_restricted(tmp_path):
    data = tmp_path / "data"
    (data / "models").mkdir(parents=True)
    f = data / "sentinel_v3.db"
    f.write_bytes(b"x")
    os.chmod(f, 0o644)
    os.chmod(data, 0o755)
    old_umask = os.umask(0o022)
    try:
        restrict_data_dir(data)
        assert stat.S_IMODE(data.stat().st_mode) == 0o700
        assert stat.S_IMODE((data / "models").stat().st_mode) == 0o700
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
        new = data / "later.db"
        new.write_bytes(b"y")  # created after start-up: private by umask
        assert stat.S_IMODE(new.stat().st_mode) & 0o077 == 0
    finally:
        os.umask(old_umask)


def test_secure_delete_is_on(identity_env):
    conn = db.get_connection()
    try:
        assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
    finally:
        conn.close()


def _sql(query, params=()):
    conn = db.get_connection()
    try:
        rows = conn.execute(query, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def test_retention_covers_personal_data_tables(identity_env):
    owner = make_user("owner.demo")
    db.create_device("dev-demo-03", owner, "host.demo", "linux", "synthetic-hash")
    closed = db.create_incident("dev-demo-03", "192.0.2.10", "brute_force", "HIGH", OLD)
    still_open = db.create_incident("dev-demo-03", "192.0.2.11", "brute_force", "HIGH", OLD)
    _sql("UPDATE incidents SET status = 'RESOLVED' WHERE id = ?", (closed,))
    _sql(
        "INSERT INTO alerts_feedback (alert_id, label, created_at) VALUES (1, 'false_positive', ?)",
        (OLD,),
    )
    _sql(
        "INSERT INTO ip_geolocation (ip_address, city, resolved_at) VALUES ('198.51.100.7', 'X', ?)",
        (OLD,),
    )
    _sql(
        "INSERT INTO threat_intel_cache (ip_address, queried_at, expires_at) VALUES ('198.51.100.8', ?, ?)",
        (OLD, OLD),
    )
    db.store_token("tok-demo-old", owner, datetime.utcnow() - timedelta(days=400))
    audit.record("test.event")  # recent audit row: must survive

    db.cleanup_old_data()

    assert db.get_incident(closed) is None
    assert db.get_incident(still_open) is not None
    for table in ("alerts_feedback", "ip_geolocation", "threat_intel_cache", "registration_tokens"):
        assert _sql(f"SELECT COUNT(*) FROM {table}")[0][0] == 0, table
    assert _sql("SELECT COUNT(*) FROM audit_events")[0][0] == 1


def test_backup_verify_restore_round_trip(identity_env, tmp_path):
    make_user("keep.demo")
    path = backup.create_backup(tmp_path / "bk")
    manifest = backup.verify_backup(path)
    assert manifest["integrity_check"] == "ok" and manifest["row_counts"]["users"] == 1
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    make_user("later.demo")
    safety = backup.restore_backup(path)
    assert safety.exists()
    assert db.get_user_by_username("keep.demo") is not None
    assert db.get_user_by_username("later.demo") is None
    assert [e["action"] for e in audit.list_events(5)][0] == "data.backup.restore"


def test_tampered_backup_is_refused(identity_env, tmp_path):
    path = backup.create_backup(tmp_path / "bk")
    with path.open("r+b") as fh:
        fh.seek(200)
        fh.write(b"\x00tampered\x00")
    with pytest.raises(backup.BackupError, match="SHA-256"):
        backup.restore_backup(path)


def test_backup_without_manifest_is_refused(identity_env, tmp_path):
    path = backup.create_backup(tmp_path / "bk")
    path.with_name(path.name + backup.MANIFEST_SUFFIX).unlink()
    with pytest.raises(backup.BackupError, match="manifest"):
        backup.verify_backup(path)
