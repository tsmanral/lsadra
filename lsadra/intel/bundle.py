"""
Bundled intel tier: find, verify, and query the signed intel-YYYYMMDD.sqlite.

Verification runs before the file is opened (ADR 0004):

1. ``manifest.sig`` verifies against a key in ``trusted_keys.json``.
2. Every source in the manifest is on the redistribution allowlist below.
3. The SQLite file's SHA-256 and size match the manifest.

Any failure disables the bundled tier (fail closed) and is reported by
``status()``; the rest of LSADRA keeps running. The verified file is opened
read-only, so nothing at runtime can write to it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from lsadra.intel import signing

logger = logging.getLogger(__name__)

PACKAGED_DIR = Path(__file__).resolve().parent / "data"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
MANIFEST_FORMAT = 1

# Sources whose licences allow redistribution inside release assets (ADR 0004).
# Keyed or licence-encumbered sources (AbuseIPDB, OTX, abuse.ch, Spamhaus,
# MaxMind) belong to the runtime tier and must never appear here.
ALLOWED_BUNDLED_SOURCES = frozenset(
    {"cisa_kev", "cisa_advisories", "mitre_attack_enterprise", "nvd"}
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class BundleError(Exception):
    """The bundle failed verification."""


@dataclass
class VerifiedBundle:
    directory: Path
    sqlite_path: Path
    manifest: Dict[str, Any]
    key_id: str


@dataclass
class _State:
    loaded: bool = False
    bundle: Optional[VerifiedBundle] = None
    error: Optional[str] = None
    candidates: List[str] = field(default_factory=list)


_state = _State()
_lock = threading.Lock()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_dir(directory: Path, trusted=None) -> VerifiedBundle:
    """Verify the bundle in ``directory``; raise BundleError on any failure."""
    manifest_path = directory / MANIFEST_NAME
    sig_path = directory / SIGNATURE_NAME
    if not manifest_path.is_file():
        raise BundleError(f"no {MANIFEST_NAME} in {directory}")
    if not sig_path.is_file():
        raise BundleError(f"no {SIGNATURE_NAME} in {directory}")

    manifest_bytes = manifest_path.read_bytes()
    try:
        key_id = signing.verify(manifest_bytes, sig_path.read_text(encoding="utf-8"), trusted)
    except signing.SignatureError as exc:
        raise BundleError(str(exc)) from exc

    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        raise BundleError("manifest is not valid JSON") from exc
    if manifest.get("format") != MANIFEST_FORMAT:
        raise BundleError(f"unsupported manifest format {manifest.get('format')!r}")

    sources = manifest.get("sources") or []
    bad = sorted({s.get("id", "?") for s in sources} - ALLOWED_BUNDLED_SOURCES)
    if bad:
        raise BundleError(f"manifest lists sources outside the bundled allowlist: {bad}")

    name = manifest.get("file", "")
    if not re.fullmatch(r"intel-\d{8}\.sqlite", name or ""):
        raise BundleError(f"unexpected bundle file name {name!r}")
    sqlite_path = directory / name
    if not sqlite_path.is_file():
        raise BundleError(f"{name} is missing")
    if sqlite_path.stat().st_size != manifest.get("size"):
        raise BundleError(f"{name} size does not match the manifest")
    if _sha256(sqlite_path) != manifest.get("sha256"):
        raise BundleError(f"{name} hash does not match the manifest")

    return VerifiedBundle(directory, sqlite_path, manifest, key_id)


def _candidate_dirs() -> List[Path]:
    from lsadra.config import INTEL_BUNDLE_DIR

    dirs = []
    if INTEL_BUNDLE_DIR:
        dirs.append(Path(INTEL_BUNDLE_DIR))
    dirs.append(PACKAGED_DIR)
    return dirs


def load(force: bool = False) -> Optional[VerifiedBundle]:
    """Verify and cache the newest usable bundle. Override dir wins if newer and valid."""
    with _lock:
        if _state.loaded and not force:
            return _state.bundle
        best: Optional[VerifiedBundle] = None
        errors = []
        candidates = []
        for d in _candidate_dirs():
            candidates.append(str(d))
            try:
                vb = verify_dir(d)
            except BundleError as exc:
                errors.append(f"{d}: {exc}")
                continue
            if best is None or vb.manifest.get("built_at", "") > best.manifest.get("built_at", ""):
                best = vb
        _state.loaded = True
        _state.bundle = best
        _state.candidates = candidates
        _state.error = None if best else "; ".join(errors) or "no bundle found"
        if best is None:
            logger.error("Bundled intel disabled: %s", _state.error)
        elif errors:
            logger.warning("Ignored intel bundle(s) that failed verification: %s", errors)
        return best


def _connect() -> Optional[sqlite3.Connection]:
    vb = load()
    if vb is None:
        return None
    conn = sqlite3.connect(f"{vb.sqlite_path.as_uri()}?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def status() -> Dict[str, Any]:
    vb = load()
    if vb is None:
        return {"available": False, "error": _state.error, "searched": _state.candidates}
    m = vb.manifest
    return {
        "available": True,
        "file": m.get("file"),
        "built_at": m.get("built_at"),
        "signed_by": vb.key_id,
        "location": "override" if vb.directory != PACKAGED_DIR else "packaged",
        "sources": [
            {
                k: s.get(k)
                for k in ("id", "name", "version", "records", "license", "url", "retrieved_at")
            }
            for s in m.get("sources", [])
        ],
    }


# ── Queries ──────────────────────────────────────────────────────────────


def _kev_row(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    d["known_ransomware_use"] = d.get("known_ransomware_use") == "Known"
    d["cwes"] = [c for c in (d.get("cwes") or "").split(",") if c]
    return d


def lookup_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    cve_id = (cve_id or "").strip().upper()
    if not _CVE_RE.match(cve_id):
        return None
    conn = _connect()
    if conn is None:
        return None
    try:
        r = conn.execute("SELECT * FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
        return _kev_row(r) if r else None
    finally:
        conn.close()


def search_kev(query: str = "", limit: int = 50) -> List[Dict[str, Any]]:
    """Newest KEV entries first, optionally filtered by CVE id, vendor, product or name."""
    limit = max(1, min(int(limit), 500))
    conn = _connect()
    if conn is None:
        return []
    try:
        q = (query or "").strip()
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            rows = conn.execute(
                """SELECT * FROM kev
                   WHERE cve_id LIKE ? ESCAPE '\\' OR vendor LIKE ? ESCAPE '\\'
                      OR product LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\'
                   ORDER BY date_added DESC, cve_id DESC LIMIT ?""",
                (like, like, like, like, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM kev ORDER BY date_added DESC, cve_id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_kev_row(r) for r in rows]
    finally:
        conn.close()


def lookup_technique(technique_id: str) -> Optional[Dict[str, Any]]:
    tid = (technique_id or "").strip().upper()
    if not _TECHNIQUE_RE.match(tid):
        return None
    conn = _connect()
    if conn is None:
        return None
    try:
        r = conn.execute("SELECT * FROM attack_technique WHERE technique_id = ?", (tid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["tactics"] = [t for t in (d.get("tactics") or "").split(",") if t]
        d["is_subtechnique"] = bool(d.get("is_subtechnique"))
        return d
    finally:
        conn.close()
