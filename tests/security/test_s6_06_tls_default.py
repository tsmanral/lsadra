"""
LSADRA security regression — §6 #6: TLS off by default.

Attacker story: agents ship their API keys to the collector over the wire. With
REQUIRE_TLS defaulting to false, a fresh deployment accepts those keys over
plaintext HTTP, exposing them to any on-path observer. The fix makes TLS
enforcement default to ON outside dev mode (LSADRA_DEV_MODE=true), while
keeping an explicit env override in both directions.

REQUIRE_TLS is computed at import, so it is read from a fresh subprocess. A JWT
secret is supplied so the §6 #4 boot guard does not fire first.
"""

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GUARDED = ("LSADRA_DEV_MODE", "LSADRA_JWT_SECRET", "LSADRA_REQUIRE_TLS")


def _require_tls(env_overrides):
    """Import lsadra.config in a clean subprocess; return str(config.REQUIRE_TLS)."""
    env = {k: v for k, v in os.environ.items() if k not in _GUARDED}
    # Provide a secret so the #4 JWT guard passes and config imports cleanly.
    env["LSADRA_JWT_SECRET"] = "test-stable-secret-not-real"
    env.update(env_overrides)
    r = subprocess.run(
        [sys.executable, "-c", "import lsadra.config as c; print(c.REQUIRE_TLS)"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_REPO_ROOT),
    )
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_tls_required_by_default_outside_dev_mode():
    """Prod default: TLS enforced."""
    assert _require_tls({}) == "True"


def test_tls_optional_in_dev_mode():
    """Dev-mode default: TLS optional for local plain-HTTP work."""
    assert _require_tls({"LSADRA_DEV_MODE": "true"}) == "False"


def test_explicit_env_overrides_prod_default():
    """An explicit LSADRA_REQUIRE_TLS=false is still honored outside dev mode."""
    assert _require_tls({"LSADRA_REQUIRE_TLS": "false"}) == "False"


def test_explicit_env_overrides_dev_default():
    """An explicit LSADRA_REQUIRE_TLS=true is honored in dev mode."""
    assert _require_tls(
        {"LSADRA_DEV_MODE": "true", "LSADRA_REQUIRE_TLS": "true"}
    ) == "True"
