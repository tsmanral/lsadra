"""
LSADRA security regression — §6 #4: JWT secret boot guard.

Attacker story: with no LSADRA_JWT_SECRET set, the server silently generated a
random per-boot secret. That invalidates every issued token on restart AND lets
an operator unknowingly run "in production" with an ephemeral, unmanaged signing
key — masking a missing-secret misconfiguration. The fix refuses to start
outside dev mode unless LSADRA_JWT_SECRET is set, and removes the silent
LSADRA_SECRET_KEY -> JWT_SECRET fallback.

The guard fires at import time, so it is exercised in a fresh subprocess with a
controlled environment (the parent test process itself runs in dev mode).
"""

import os
import subprocess
import sys
from pathlib import Path

# tests/security/<this> -> parents[2] == repo root (has the `lsadra` package).
_REPO_ROOT = Path(__file__).resolve().parents[2]

_GUARDED_VARS = ("LSADRA_DEV_MODE", "LSADRA_JWT_SECRET", "LSADRA_SECRET_KEY")


def _boot(env_overrides, code="import lsadra.config"):
    """Import lsadra.config in a clean subprocess; return the CompletedProcess."""
    env = {k: v for k, v in os.environ.items() if k not in _GUARDED_VARS}
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_REPO_ROOT),
    )


def test_refuses_boot_without_secret_outside_dev_mode():
    """No dev mode + no secret -> refuse to start (non-zero exit, clear reason)."""
    r = _boot({})
    assert r.returncode != 0, "config booted without a JWT secret outside dev mode"
    assert "LSADRA_JWT_SECRET is required" in r.stderr


def test_boots_with_explicit_secret():
    """An explicit stable secret satisfies the guard even outside dev mode."""
    r = _boot({"LSADRA_JWT_SECRET": "test-stable-secret-not-real"})
    assert r.returncode == 0, r.stderr


def test_dev_mode_boots_with_random_secret():
    """Dev mode is allowed to fall back to a per-boot random secret."""
    r = _boot({"LSADRA_DEV_MODE": "true"})
    assert r.returncode == 0, r.stderr


def test_secret_key_fallback_removed():
    """The silent SECRET_KEY -> JWT_SECRET alias is gone (no SECRET_KEY attr)."""
    r = _boot(
        {"LSADRA_DEV_MODE": "true"},
        code="import lsadra.config as c; print(hasattr(c, 'SECRET_KEY'))",
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "False"


def test_secret_key_env_alone_does_not_satisfy_guard():
    """Setting only the OLD LSADRA_SECRET_KEY alias must NOT satisfy the guard."""
    r = _boot({"LSADRA_SECRET_KEY": "old-alias-should-not-work"})
    assert r.returncode != 0
    assert "LSADRA_JWT_SECRET is required" in r.stderr
