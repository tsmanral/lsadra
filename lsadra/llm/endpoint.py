"""
Where the LLM tier may send prompts, and which weights it may load (G-30).

* A bring-your-own-model endpoint must be on this machine (a loopback IP or
  ``localhost``) unless the operator opts in with ``LSADRA_LLM_ALLOW_REMOTE``.
  A remote endpoint must use HTTPS. Incident data never leaves the host by
  default; the lite tier needs no API keys.
* Downloaded GGUF or ONNX weights load only if their SHA-256 matches a pin:
  an entry in ``pinned_models.json`` (shipped with the release and covered by
  its signed manifest) or the operator's own ``LSADRA_LLM_MODEL_SHA256``.
"""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlsplit

from lsadra.models.integrity import ModelIntegrityError, verify_pinned_file

PINNED_MODELS_PATH = Path(__file__).with_name("pinned_models.json")


class EndpointNotAllowed(ValueError):
    """The configured LLM endpoint violates the locality policy."""


def _allow_remote_default() -> bool:
    return os.getenv("LSADRA_LLM_ALLOW_REMOTE", "false").lower() == "true"


def validate_llm_endpoint(url: str, allow_remote: Optional[bool] = None) -> str:
    """Return *url* if the policy allows it, else raise :class:`EndpointNotAllowed`."""
    allow_remote = _allow_remote_default() if allow_remote is None else allow_remote
    parts = urlsplit(url or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise EndpointNotAllowed("LLM endpoint must be an http(s) URL with a host")
    if parts.username or parts.password:
        raise EndpointNotAllowed("credentials in the endpoint URL are not allowed")

    host = parts.hostname.rstrip(".").lower()
    loopback = host == "localhost"
    if not loopback:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False

    if loopback:
        return url
    if not allow_remote:
        raise EndpointNotAllowed(
            "LLM endpoint is not on this machine; set LSADRA_LLM_ALLOW_REMOTE=true to send "
            "incident data to a remote model"
        )
    if parts.scheme != "https":
        raise EndpointNotAllowed("a remote LLM endpoint must use https")
    return url


def pinned_models() -> Dict[str, str]:
    """File name -> SHA-256 for model weights this release knows about."""
    try:
        data = json.loads(PINNED_MODELS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    return {str(k): str(v["sha256"]) for k, v in data.get("models", {}).items()}


def verify_model_weights(path: Path, expected_sha256: Optional[str] = None) -> Path:
    """Refuse weights whose hash is not pinned (release pin or operator override)."""
    path = Path(path)
    expected = expected_sha256 or os.getenv("LSADRA_LLM_MODEL_SHA256") or pinned_models().get(path.name)
    if not expected:
        raise ModelIntegrityError(
            f"{path.name} has no pinned SHA-256; set LSADRA_LLM_MODEL_SHA256 for a model you chose"
        )
    return verify_pinned_file(path, expected)
