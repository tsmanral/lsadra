"""Backup and restore for the LSADRA database (G-27, CIS 11.1 to 11.4).

    python -m lsadra.backup create  [--out DIR]
    python -m lsadra.backup verify  FILE
    python -m lsadra.backup restore FILE --yes

``create`` copies the live database with SQLite's online backup API (safe while
the server runs), checks the copy with ``PRAGMA integrity_check`` and writes a
manifest beside it: SHA-256, size, applied migrations and row counts. Backups
default to ``data/backups/`` and are created 0600 (the directory 0700).

``restore`` verifies the file against its manifest and its integrity first,
saves the current database as ``pre-restore-<time>.db`` next to the backups,
then copies the backup into place with the same online API and runs any newer
migrations. Stop the server before restoring so it does not keep writing to the
database it is about to lose.

Each create and restore is written to the audit trail.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


MANIFEST_SUFFIX = ".manifest.json"


class BackupError(RuntimeError):
    pass


def _db_path() -> Path:
    from lsadra.storage import database

    return Path(database.DB_PATH)


def default_backup_dir() -> Path:
    return _db_path().parent / "backups"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)


def _integrity(path: Path) -> str:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return str(conn.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        conn.close()


def _summary(path: Path) -> Dict[str, Any]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        counts = {t: conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in tables}
        try:
            migrations = [r[0] for r in conn.execute("SELECT filename FROM _schema_migrations ORDER BY id")]
        except sqlite3.OperationalError:
            migrations = []
    finally:
        conn.close()
    return {"row_counts": counts, "migrations": migrations}


def _copy(src: Path, dst: Path) -> None:
    """Online copy src -> dst with the SQLite backup API."""
    source = sqlite3.connect(str(src), timeout=30)
    target = sqlite3.connect(str(dst), timeout=30)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def create_backup(out_dir: Optional[Path] = None) -> Path:
    src = _db_path()
    if not src.exists():
        raise BackupError(f"No database at {src}.")
    out_dir = Path(out_dir) if out_dir else default_backup_dir()
    _private_dir(out_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dst = out_dir / f"lsadra-{stamp}.db"
    fd = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    _copy(src, dst)
    check = _integrity(dst)
    if check != "ok":
        dst.unlink(missing_ok=True)
        raise BackupError(f"Backup failed its integrity check: {check}")
    manifest = {
        "format": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "file": dst.name,
        "sha256": _sha256(dst),
        "size_bytes": dst.stat().st_size,
        "integrity_check": check,
        **_summary(dst),
    }
    manifest_path = dst.with_name(dst.name + MANIFEST_SUFFIX)
    fd = os.open(str(manifest_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    _audit("data.backup.create", dst, manifest["sha256"])
    return dst


def verify_backup(path: Path) -> Dict[str, Any]:
    path = Path(path)
    manifest_path = path.with_name(path.name + MANIFEST_SUFFIX)
    if not path.exists():
        raise BackupError(f"No backup at {path}.")
    if not manifest_path.exists():
        raise BackupError(f"No manifest at {manifest_path}; refusing an unverifiable backup.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    actual = _sha256(path)
    if actual != manifest.get("sha256"):
        raise BackupError("Backup does not match its manifest's SHA-256; it was changed or damaged.")
    check = _integrity(path)
    if check != "ok":
        raise BackupError(f"Backup failed its integrity check: {check}")
    return manifest


def restore_backup(path: Path) -> Path:
    """Restore *path* over the live database; returns the pre-restore safety copy."""
    path = Path(path)
    verify_backup(path)
    live = _db_path()
    safety_dir = default_backup_dir()
    _private_dir(safety_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safety = safety_dir / f"pre-restore-{stamp}.db"
    if live.exists():
        fd = os.open(str(safety), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        _copy(live, safety)
    else:
        _private_dir(live.parent)
    _copy(path, live)
    from lsadra.storage.database import init_db

    init_db()  # bring an older backup up to the current schema
    _audit("data.backup.restore", path, _sha256(path), {"safety_copy": safety.name})
    return safety


def _audit(action: str, path: Path, digest: str, extra: Optional[Dict[str, Any]] = None) -> None:
    from lsadra.security import audit

    audit.record(action, actor={"user_id": None, "username": "server-cli"},
                 target=path.name, details={"sha256": digest, **(extra or {})})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lsadra.backup")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="back up the live database")
    c.add_argument("--out", type=Path, default=None)
    v = sub.add_parser("verify", help="check a backup against its manifest")
    v.add_argument("file", type=Path)
    r = sub.add_parser("restore", help="replace the live database with a backup")
    r.add_argument("file", type=Path)
    r.add_argument("--yes", action="store_true", help="confirm: the current database is replaced")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "create":
            from lsadra.storage.database import init_db

            init_db()
            out = create_backup(args.out)
            print(f"Backup written: {out}")
        elif args.cmd == "verify":
            m = verify_backup(args.file)
            print(f"OK: {args.file} (sha256 {m['sha256']}, created {m['created_at']})")
        else:
            if not args.yes:
                print("Restore replaces the current database. Stop the server, then re-run with --yes.",
                      file=sys.stderr)
                return 2
            safety = restore_backup(args.file)
            print(f"Restored {args.file}. The previous database was saved as {safety}.")
    except BackupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
