"""Regression test for §6 #11 — Client-side mock credentials and offline login.

Attacker story: A production SPA build shipped an offline `login()` fallback whose
`SEED_CREDS` table unconditionally contained `admin`/`admin` (plus demo users). When
the backend was offline, the browser authenticated `admin`/`admin` client-side and
granted an ADMIN session with no server involvement at all.

Commit c78e30a gated the seed behind `import.meta.env.DEV`, but the fallback itself
stayed: `login()` still fell back to `resolveCred()` on any backend error, reading
passwords that `setMockCred` wrote to `sentinel_mock_creds` in localStorage in every
build. At M3 the whole path is deleted: the browser never resolves credentials or
mints a token, and only the server's `POST /api/auth/login` response sets one.

There is no JS/TS runtime in this Python harness, so these are SOURCE-TEXT INVARIANT
checks over frontend/src. Restoring any part of the offline login (the seed table, the
credential store, the client-minted `mock-` token) FAILS them.
"""

import pathlib
import re

# tests/security/test_s6_11_mock_creds.py -> parents[2] == repo root
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"
API_TS = FRONTEND_SRC / "services" / "api.ts"

# Identifiers of the deleted offline-login path.
OFFLINE_LOGIN_SYMBOLS = ("SEED_CREDS", "resolveCred", "getMockCreds", "setMockCred", "setMockRole")


def _sources() -> dict:
    files = sorted(FRONTEND_SRC.rglob("*.ts")) + sorted(FRONTEND_SRC.rglob("*.tsx"))
    assert API_TS in files, f"expected frontend source at {API_TS}"
    return {path: path.read_text(encoding="utf-8") for path in files}


def test_no_client_side_credential_resolution():
    """None of the offline-login helpers or the seed table may exist anywhere."""
    for path, source in _sources().items():
        for symbol in OFFLINE_LOGIN_SYMBOLS:
            assert not re.search(rf"\b{symbol}\b", source), (
                f"{path.relative_to(REPO_ROOT)} contains `{symbol}` — the offline "
                "mock login is back (§6 #11 regression)."
            )


def test_no_seeded_admin_password():
    """No default admin/admin credential may be shipped in the SPA, gated or not."""
    for path, source in _sources().items():
        assert not re.search(r"admin\s*:\s*\{\s*password\s*:", source), (
            f"{path.relative_to(REPO_ROOT)} seeds an admin password client-side (§6 #11)."
        )


def test_stored_mock_credentials_are_never_read():
    """`sentinel_mock_creds` may only be cleared (old builds left plaintext
    passwords there), never read back."""
    for path, source in _sources().items():
        for match in re.finditer(r"sentinel_mock_creds", source):
            line = source[source.rfind("\n", 0, match.start()) + 1 : source.find("\n", match.end())]
            assert "removeItem" in line, (
                f"{path.relative_to(REPO_ROOT)} uses `sentinel_mock_creds` other than "
                f"to clear it: {line.strip()!r} (§6 #11)."
            )


def test_login_never_mints_a_token():
    """`login()` must not fabricate a session token when the backend fails."""
    source = API_TS.read_text(encoding="utf-8")
    start = source.find("export const login")
    assert start != -1, "could not locate `login` in api.ts"
    end = source.find("\n};", start)
    assert end != -1, "could not locate the end of `login` in api.ts"
    body = source[start:end]
    assert "sentinel_token" not in body, (
        "login() writes sentinel_token itself; only the server's response may "
        "supply a token (§6 #11)."
    )
    assert "mock-" not in body, "login() builds a client-side `mock-` token (§6 #11)."
