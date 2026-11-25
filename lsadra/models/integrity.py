"""
Model file integrity (G-17).

Every file the detection stack persists (pickled scikit-learn ensembles, JSON
autoencoder weights, JSON baselines, model cards) goes through a :class:`ModelStore`. The
store keeps a ``manifest.json`` in the same folder listing each file's SHA-256
and size, and authenticates the manifest with an HMAC keyed by a secret that
does not live in the models folder (``LSADRA_MODEL_SIGNING_KEY``, or a key
derived from ``LSADRA_JWT_SECRET``).

A file is only deserialized after its bytes have been read once, hashed, and
matched against an authenticated manifest entry; the verified bytes are what
get deserialized, so the file cannot change between the check and the load.
Anything else (no manifest, a manifest with a bad HMAC, a file the manifest
does not list, a hash or size mismatch) raises :class:`ModelIntegrityError`,
and callers fall back to training fresh models instead of loading.

Downloaded third-party weights (ONNX, GGUF) are checked with
:func:`verify_pinned_file` against a SHA-256 pinned in code or in a signed
release manifest, before any runtime opens them.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 1
_KEY_CONTEXT = b"lsadra/model-manifest/v1"

# One lock per process guards manifest read-modify-write across stores.
_MANIFEST_LOCK = threading.RLock()


class ModelIntegrityError(RuntimeError):
    """A model file could not be verified and must not be loaded."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def signing_key() -> bytes:
    """The manifest HMAC key. Read at call time so tests and key rotation apply."""
    from lsadra import config

    explicit = os.getenv("LSADRA_MODEL_SIGNING_KEY") or config.MODEL_SIGNING_KEY
    if explicit:
        return hashlib.sha256(explicit.encode("utf-8")).digest()
    return hmac.new(config.JWT_SECRET.encode("utf-8"), _KEY_CONTEXT, hashlib.sha256).digest()


def _canonical(files: Dict[str, Any]) -> bytes:
    return json.dumps(
        {"version": MANIFEST_VERSION, "files": files}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sign(files: Dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical(files), hashlib.sha256).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    """Write *data* to *path* via a temp file in the same folder and a rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _check_name(name: str) -> str:
    """Store names are plain file names: no folders, no traversal, no manifest."""
    if (
        not name
        or name != Path(name).name
        or name in (".", "..", MANIFEST_NAME)
        or name.startswith(".")
    ):
        raise ValueError(f"invalid model file name: {name!r}")
    return name


class ModelStore:
    """A folder of model files guarded by an HMAC-authenticated manifest."""

    def __init__(self, directory: Path):
        self.dir = Path(directory)

    # ── manifest ──────────────────────────────────────────────────────────

    @property
    def manifest_path(self) -> Path:
        return self.dir / MANIFEST_NAME

    def _read_manifest(self) -> Dict[str, Any]:
        """Authenticated file table. Raises ModelIntegrityError if not trustworthy."""
        try:
            raw = self.manifest_path.read_bytes()
        except FileNotFoundError:
            raise ModelIntegrityError(f"no model manifest in {self.dir}") from None
        try:
            doc = json.loads(raw)
            files = doc["files"]
            mac = doc["hmac"]
            if doc.get("version") != MANIFEST_VERSION or not isinstance(files, dict):
                raise ValueError("unsupported manifest")
        except (ValueError, KeyError, TypeError) as exc:
            raise ModelIntegrityError(f"unreadable model manifest in {self.dir}") from exc
        if not isinstance(mac, str) or not hmac.compare_digest(mac, _sign(files, signing_key())):
            raise ModelIntegrityError(f"model manifest in {self.dir} failed authentication")
        return files

    def _files_or_empty(self) -> Dict[str, Any]:
        """Current file table for updating; an untrusted manifest starts over empty."""
        try:
            return self._read_manifest()
        except ModelIntegrityError:
            return {}

    def _write_manifest(self, files: Dict[str, Any]) -> None:
        doc = {"version": MANIFEST_VERSION, "files": files, "hmac": _sign(files, signing_key())}
        _atomic_write(self.manifest_path, json.dumps(doc, indent=2, sort_keys=True).encode("utf-8"))

    def entries(self) -> Dict[str, Any]:
        """Verified manifest entries (empty if the manifest is missing or untrusted)."""
        with _MANIFEST_LOCK:
            return dict(self._files_or_empty())

    # ── raw bytes ─────────────────────────────────────────────────────────

    def write_bytes(self, name: str, data: bytes) -> str:
        """Write a file and record its hash in the manifest. Returns the SHA-256."""
        _check_name(name)
        digest = sha256_bytes(data)
        with _MANIFEST_LOCK:
            files = self._files_or_empty()
            _atomic_write(self.dir / name, data)
            files[name] = {
                "sha256": digest,
                "size": len(data),
                "written_at": datetime.now(timezone.utc).isoformat(),
            }
            self._write_manifest(files)
        return digest

    def read_verified(self, name: str) -> bytes:
        """Return the file's bytes only if they match the authenticated manifest."""
        _check_name(name)
        path = self.dir / name
        with _MANIFEST_LOCK:
            files = self._read_manifest()
            entry = files.get(name)
            if not isinstance(entry, dict):
                raise ModelIntegrityError(f"{name} is not listed in the model manifest")
            try:
                if path.is_symlink():
                    raise ModelIntegrityError(f"{name} is a symlink; refusing to load")
                data = path.read_bytes()
            except FileNotFoundError:
                raise ModelIntegrityError(f"{name} is listed but missing") from None
        if len(data) != entry.get("size") or not hmac.compare_digest(
            sha256_bytes(data), str(entry.get("sha256", ""))
        ):
            raise ModelIntegrityError(f"{name} does not match its manifest hash")
        return data

    def exists(self, name: str) -> bool:
        return (self.dir / _check_name(name)).exists()

    def sha256(self, name: str) -> Optional[str]:
        entry = self.entries().get(name)
        return entry.get("sha256") if isinstance(entry, dict) else None

    def remove(self, name: str) -> None:
        _check_name(name)
        with _MANIFEST_LOCK:
            files = self._files_or_empty()
            files.pop(name, None)
            try:
                (self.dir / name).unlink()
            except FileNotFoundError:
                pass
            self._write_manifest(files)

    def clear(self) -> None:
        """Delete every file the manifest lists and leave an empty, signed manifest.

        Only listed files are touched, so sub-folders (``previous/``) survive.
        """
        with _MANIFEST_LOCK:
            for name in self._files_or_empty():
                try:
                    (self.dir / _check_name(name)).unlink()
                except (FileNotFoundError, ValueError):
                    pass
            self._write_manifest({})

    # ── typed helpers ─────────────────────────────────────────────────────

    def save_joblib(self, name: str, obj: Any) -> str:
        import joblib

        buf = io.BytesIO()
        joblib.dump(obj, buf)
        return self.write_bytes(name, buf.getvalue())

    def load_joblib(self, name: str) -> Any:
        import joblib

        return joblib.load(io.BytesIO(self.read_verified(name)))

    def save_json(self, name: str, obj: Any) -> str:
        return self.write_bytes(name, json.dumps(obj, indent=2, sort_keys=True).encode("utf-8"))

    def load_json(self, name: str) -> Any:
        return json.loads(self.read_verified(name))

    # ── snapshots (rollback) ──────────────────────────────────────────────

    def copy_verified_to(self, other: "ModelStore") -> int:
        """Copy every verified file into *other*, replacing its contents.

        Files that fail verification are skipped (and logged), so a snapshot
        never launders a tampered file into a trusted manifest.
        """
        with _MANIFEST_LOCK:
            files = self._files_or_empty()
            other.clear()
            copied = 0
            for name in sorted(files):
                try:
                    data = self.read_verified(name)
                except (ModelIntegrityError, ValueError) as exc:
                    logger.warning("Skipping unverified model file %s: %s", name, exc)
                    continue
                other.write_bytes(name, data)
                copied += 1
            return copied


def verify_pinned_file(path: Path, expected_sha256: str) -> Path:
    """Raise unless *path* hashes to *expected_sha256* (for downloaded ONNX/GGUF weights)."""
    path = Path(path)
    if not expected_sha256 or len(expected_sha256) != 64:
        raise ModelIntegrityError(f"no pinned SHA-256 for {path.name}")
    if path.is_symlink() or not path.is_file():
        raise ModelIntegrityError(f"{path.name} is not a regular file")
    if not hmac.compare_digest(sha256_file(path), expected_sha256.lower()):
        raise ModelIntegrityError(f"{path.name} does not match its pinned SHA-256")
    return path
