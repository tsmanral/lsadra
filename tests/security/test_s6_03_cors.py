"""
LSADRA security regression — §6 #3: CORS wildcard + credentials.

Attacker story: with ``allow_origins=["*"]`` AND ``allow_credentials=True``, any
website could make credentialed cross-origin requests to the API and read the
responses — a classic CORS misconfiguration (browsers reflect the caller's
Origin when credentials are combined with a wildcard). The fix drops
credentialed CORS entirely (agents use header-token auth, not browser cookies)
and restricts origins to an env-driven allowlist that is empty by default.

Behavior is asserted via Starlette's CORSMiddleware through the test client. On
the pre-fix config a disallowed Origin is reflected back with credentials;
post-fix it is not — so these assertions fail on the pre-fix code path.

Synthetic origins only.
"""

import pytest

from tests.fixtures import setup_test_db

_EVIL_ORIGIN = "https://evil.example"


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    setup_test_db(tmp_path)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from server import app

    return TestClient(app)


def test_disallowed_origin_not_reflected(client):
    """A non-allowlisted Origin must NOT be reflected into ACAO, and never '*'."""
    r = client.get("/api/health", headers={"Origin": _EVIL_ORIGIN})
    acao = r.headers.get("access-control-allow-origin")
    assert acao != "*"
    assert acao != _EVIL_ORIGIN


def test_no_credentialed_cors(client):
    """Credentialed CORS must be disabled (no cookies -> no ACA-Credentials)."""
    r = client.get("/api/health", headers={"Origin": _EVIL_ORIGIN})
    assert r.headers.get("access-control-allow-credentials") != "true"


def test_preflight_from_disallowed_origin_not_granted(client):
    """A CORS preflight from a disallowed origin must not be granted the origin."""
    r = client.options(
        "/api/events/batch",
        headers={
            "Origin": _EVIL_ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )
    acao = r.headers.get("access-control-allow-origin")
    assert acao != "*"
    assert acao != _EVIL_ORIGIN
    assert r.headers.get("access-control-allow-credentials") != "true"
