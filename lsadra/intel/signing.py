"""
Ed25519 signing for the bundled intel tier (ADR 0004).

The bundled intel DB feeds every downstream detection and the narrative
engine, so it is a poisoning target. Each bundle ships with a manifest that
lists the SQLite file's SHA-256 and its sources; the manifest bytes are signed
with Ed25519. The loader trusts only the public keys in ``trusted_keys.json``.

The private key never lives in the repository. Releases sign with the key held
in the ``LSADRA_INTEL_SIGNING_KEY`` GitHub Actions secret (see
``.github/workflows/intel-bundle.yml``); ``python -m lsadra.intel keygen``
creates a new pair for rotation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

logger = logging.getLogger(__name__)

TRUSTED_KEYS_PATH = Path(__file__).resolve().parent / "trusted_keys.json"


class SignatureError(Exception):
    """The manifest signature is missing, malformed, or does not verify."""


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """A short, stable id for a public key: first 16 hex chars of its SHA-256."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_keypair() -> Tuple[str, str, str]:
    """Return (key_id, private_key_b64, public_key_b64) for a new Ed25519 pair."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return (
        key_id_for(pub),
        base64.b64encode(priv_raw).decode(),
        base64.b64encode(pub_raw).decode(),
    )


def load_private_key(private_key_b64: str) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64.strip()))
    except Exception as exc:  # malformed base64 or wrong length
        raise SignatureError("signing key is not a base64 raw Ed25519 private key") from exc


def load_trusted_keys(path: Path | None = None) -> Dict[str, Ed25519PublicKey]:
    """Map key_id -> public key. A key whose id does not match its bytes is skipped."""
    path = path or TRUSTED_KEYS_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    keys: Dict[str, Ed25519PublicKey] = {}
    for entry in data.get("keys", []):
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["public_key"]))
        except Exception as exc:
            logger.warning("Skipping unreadable trusted intel key %r: %s", entry.get("key_id"), exc)
            continue
        if key_id_for(pub) == entry.get("key_id"):
            keys[entry["key_id"]] = pub
    return keys


def sign(manifest_bytes: bytes, private_key: Ed25519PrivateKey) -> str:
    """Return the detached signature file contents (JSON) for these manifest bytes."""
    sig = private_key.sign(manifest_bytes)
    return (
        json.dumps(
            {
                "alg": "Ed25519",
                "key_id": key_id_for(private_key.public_key()),
                "signature": base64.b64encode(sig).decode(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def verify(
    manifest_bytes: bytes,
    signature_text: str,
    trusted: Dict[str, Ed25519PublicKey] | None = None,
) -> str:
    """Verify a detached signature; return the signing key_id or raise SignatureError."""
    if trusted is None:
        trusted = load_trusted_keys()
    try:
        sig = json.loads(signature_text)
        key_id = sig["key_id"]
        raw = base64.b64decode(sig["signature"])
    except Exception as exc:
        raise SignatureError("signature file is malformed") from exc
    if sig.get("alg") != "Ed25519":
        raise SignatureError("unsupported signature algorithm")
    pub = trusted.get(key_id)
    if pub is None:
        raise SignatureError(f"signing key {key_id} is not trusted")
    try:
        pub.verify(raw, manifest_bytes)
    except InvalidSignature as exc:
        raise SignatureError("signature does not match the manifest") from exc
    return key_id
