"""
LSADRA security regression — §6 #14: Spoofable X-Forwarded-Proto TLS bypass.

Attacker story: a plain-HTTP client sets ``X-Forwarded-Proto: https`` to sail
past ``TLSEnforcementMiddleware`` even though the real socket scheme is ``http``,
because the header used to be trusted from *any* peer. The fix (commit dd3eb12)
only honors X-Forwarded-Proto when the direct peer (``request.client.host``) is
listed in ``TRUSTED_PROXY_IPS``; otherwise the real ``request.url.scheme`` is
used. These tests pin that behavior and FAIL on the pre-fix code path (where the
spoofed header would flip the scheme to "https" and the request would pass).

All values are synthetic (test-device-001, 203.0.113.x, 10.0.0.5).
"""

import asyncio

import pytest

import lsadra.config as config
import lsadra.tls_middleware as tls_middleware
from lsadra.tls_middleware import TLSEnforcementMiddleware


# ---------------------------------------------------------------------------
# Synthetic request / helpers (no real socket, no DB, no TestClient needed —
# dispatch() is exercised directly as a coroutine).
# ---------------------------------------------------------------------------
class _FakeURL:
    def __init__(self, scheme, path):
        self.scheme = scheme
        self.path = path


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, scheme, path, client_host, headers=None):
        self.url = _FakeURL(scheme, path)
        self.client = _FakeClient(client_host) if client_host is not None else None
        # Starlette headers are case-insensitive; lower-case keys suffice here
        # because dispatch() reads the lower-case "x-forwarded-proto".
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}


class _SpyCallNext:
    """Records whether it was awaited; returns a sentinel pass-through response."""

    SENTINEL = object()

    def __init__(self):
        self.awaited = False

    async def __call__(self, request):
        self.awaited = True
        return self.SENTINEL


def _dispatch(request, call_next):
    """Run the middleware's async dispatch() to completion synchronously."""
    mw = TLSEnforcementMiddleware(app=lambda *a, **k: None)
    return asyncio.run(mw.dispatch(request, call_next))


# A non-exempt path. _EXEMPT_PATHS = {"/", "/api/health", "/docs",
# "/openapi.json", "/redoc"} — "/heartbeat" is deliberately NOT in that set.
NON_EXEMPT_PATH = "/heartbeat"


@pytest.fixture(autouse=True)
def _require_tls(monkeypatch):
    """Force TLS enforcement on. Patch the by-value import in the middleware
    module (config-only patching is a silent no-op)."""
    monkeypatch.setattr(tls_middleware, "REQUIRE_TLS", True)
    yield


class TestXForwardedProtoSpoof:
    """§6 #14 — X-Forwarded-Proto must not be trusted from arbitrary clients."""

    def test_spoofed_header_from_untrusted_client_is_ignored(self, monkeypatch):
        """CORE REGRESSION: http request + forged 'x-forwarded-proto: https'
        from a client NOT in TRUSTED_PROXY_IPS -> 403, call_next never awaited."""
        monkeypatch.setattr(
            tls_middleware, "TRUSTED_PROXY_IPS", frozenset({"10.0.0.5"})
        )
        request = _FakeRequest(
            scheme="http",
            path=NON_EXEMPT_PATH,
            client_host="203.0.113.9",  # untrusted attacker
            headers={"x-forwarded-proto": "https"},
        )
        call_next = _SpyCallNext()

        response = _dispatch(request, call_next)

        assert response.status_code == 403
        assert response.body == (
            b'{"detail":"TLS is required. Use HTTPS to access this endpoint."}'
        )
        assert call_next.awaited is False, "call_next must NOT run on a blocked request"

    def test_header_honored_only_from_trusted_proxy(self, monkeypatch):
        """Same forged header, but the direct peer IS a trusted proxy ->
        header honored, scheme becomes 'https', request passes through."""
        monkeypatch.setattr(
            tls_middleware, "TRUSTED_PROXY_IPS", frozenset({"10.0.0.5"})
        )
        request = _FakeRequest(
            scheme="http",
            path=NON_EXEMPT_PATH,
            client_host="10.0.0.5",  # the trusted reverse proxy
            headers={"x-forwarded-proto": "https"},
        )
        call_next = _SpyCallNext()

        response = _dispatch(request, call_next)

        assert call_next.awaited is True
        assert response is _SpyCallNext.SENTINEL

    def test_default_trusted_proxy_set_is_empty_never_trusts(self, monkeypatch):
        """With TRUSTED_PROXY_IPS at its real default (empty frozenset), no peer
        is ever trusted, so the forged header cannot bypass TLS -> 403."""
        monkeypatch.setattr(tls_middleware, "TRUSTED_PROXY_IPS", frozenset())
        request = _FakeRequest(
            scheme="http",
            path=NON_EXEMPT_PATH,
            client_host="203.0.113.42",
            headers={"x-forwarded-proto": "https"},
        )
        call_next = _SpyCallNext()

        response = _dispatch(request, call_next)

        assert response.status_code == 403
        assert call_next.awaited is False

    def test_config_default_trusted_proxy_ips_is_empty(self):
        """Guard the source default: unset LSADRA_TRUSTED_PROXY_IPS -> empty
        frozenset (fail-closed). Only meaningful when the env var is unset."""
        import os

        if os.getenv("LSADRA_TRUSTED_PROXY_IPS"):
            pytest.skip("LSADRA_TRUSTED_PROXY_IPS is set in this environment")
        assert config.TRUSTED_PROXY_IPS == frozenset()

    def test_genuine_https_from_untrusted_client_passes(self, monkeypatch):
        """A real HTTPS socket (no forged header) always passes, regardless of
        whether the client is a trusted proxy."""
        monkeypatch.setattr(tls_middleware, "TRUSTED_PROXY_IPS", frozenset())
        request = _FakeRequest(
            scheme="https",
            path=NON_EXEMPT_PATH,
            client_host="203.0.113.9",
        )
        call_next = _SpyCallNext()

        response = _dispatch(request, call_next)

        assert call_next.awaited is True
        assert response is _SpyCallNext.SENTINEL

    def test_exempt_path_passes_over_http_from_untrusted_client(self, monkeypatch):
        """Exempt health path is reachable over plain http even from an
        untrusted client (probes/LB behavior preserved)."""
        monkeypatch.setattr(tls_middleware, "TRUSTED_PROXY_IPS", frozenset())
        request = _FakeRequest(
            scheme="http",
            path="/api/health",  # exempt
            client_host="203.0.113.9",
        )
        call_next = _SpyCallNext()

        response = _dispatch(request, call_next)

        assert call_next.awaited is True
        assert response is _SpyCallNext.SENTINEL
