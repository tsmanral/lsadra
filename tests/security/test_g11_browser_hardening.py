"""
G-11 — Security headers, CSP, no API inventory or exception text, and the
dashboard trusts only the server's incident status.

Attacker story: API responses carried no CSP, nosniff or framing policy and
could be cached; the OpenAPI schema advertised every route on a production
install; some errors echoed exception text; and the dashboard let a value in
the browser's localStorage override (and fake) an incident's server status,
reporting "Saved locally" when the server refused the change.

Secure behavior pinned here: every API response sets CSP (default-src 'none';
frame-ancestors 'none'), nosniff, X-Frame-Options, Referrer-Policy,
no-store and a request ID; HSTS on HTTPS; /docs and /openapi.json are off
outside dev mode; an unhandled error returns a generic body with the request
ID; token errors do not echo library text; the production dashboard build has
a CSP and incident status comes from the server only. SYNTHETIC data only.
"""

import os
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from lsadra.security.headers import SecurityHeadersMiddleware, install_error_handlers
from tests.security._identity_support import identity_env  # noqa: F401 — fixture

ROOT = Path(__file__).resolve().parents[2]


def test_api_responses_carry_security_headers(identity_env):
    r = identity_env.get("/api/health")
    h = r.headers
    assert "default-src 'none'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"
    assert h["cache-control"] == "no-store"
    assert len(h["x-request-id"]) >= 8
    assert "strict-transport-security" not in h  # plain HTTP: no HSTS


def test_hsts_on_https(identity_env):
    client = TestClient(identity_env.app, base_url="https://testserver")
    assert "max-age=" in client.get("/api/health").headers["strict-transport-security"]


def test_unhandled_error_is_generic_with_request_id():
    app = FastAPI()
    install_error_handlers(app)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/boom")
    def boom():
        raise RuntimeError("db password is hunter2-demo")

    r = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500
    body = r.json()
    assert body["detail"] == "Internal server error." and body["request_id"]
    assert "hunter2" not in r.text


def test_invalid_token_detail_does_not_echo_library_text(identity_env):
    r = identity_env.get("/api/incidents", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid or expired token."


def test_openapi_inventory_is_off_outside_dev_mode():
    code = (
        "from fastapi.testclient import TestClient\n"
        "import server\n"
        "c = TestClient(server.app)\n"
        "print(c.get('/openapi.json').status_code, c.get('/docs').status_code)\n"
    )
    env = {**os.environ, "LSADRA_DEV_MODE": "false", "LSADRA_JWT_SECRET": "synthetic-test-secret-" + "x" * 24,
           "LSADRA_SCHEDULER_ENABLED": "false"}
    env.pop("LSADRA_EXPOSE_API_DOCS", None)
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip().splitlines()[-1] == "404 404"


def test_dashboard_build_sets_a_csp():
    vite = (ROOT / "frontend" / "vite.config.ts").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in vite and "script-src 'self'" in vite
    assert "apply: 'build'" in vite


def test_dashboard_does_not_let_local_state_override_incident_status():
    api = (ROOT / "frontend" / "src" / "services" / "api.ts").read_text(encoding="utf-8")
    assert "Saved locally" not in api
    assert "Merge local resolutions" not in api
    assert "FORCE correct closed_incidents" not in api
