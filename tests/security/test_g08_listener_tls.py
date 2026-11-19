"""
G-8 — Loopback by default; no plain HTTP beyond loopback; pinnable server identity.

Attacker story: the API bound every interface and the shipped configuration
turned TLS off, so device keys and logins crossed the network in clear, and an
agent had no way to tell the real server from an impostor at enrolment.

Secure behavior pinned here: LSADRA_API_HOST defaults to 127.0.0.1; a
non-loopback listener gets TLS (configured, or a generated self-signed
certificate stored 0600) unless TLS ends at a trusted proxy or plain HTTP is
explicitly allowed; the certificate fingerprint is served for pinning; the
Linux agent talks only to a server whose certificate matches the pin and
refuses plain http:// while pinned. SYNTHETIC data only.
"""

import http.server
import os
import ssl
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from lsadra.endpoint_agent import linux_agent
from lsadra.security import tls
from tests.security._identity_support import (  # noqa: F401 — fixture
    bearer,
    identity_env,
    login,
    make_user,
)

ROOT = Path(__file__).resolve().parents[2]


def test_default_bind_is_loopback():
    env = {k: v for k, v in os.environ.items() if k != "LSADRA_API_HOST"}
    out = subprocess.run([sys.executable, "-c", "from lsadra import config; print(config.API_HOST)"],
                         cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "127.0.0.1"


def test_loopback_may_serve_plain_http(tmp_path):
    plan = tls.plan_listener("127.0.0.1", 8000, cert="", key="", trusted_proxies=frozenset(),
                             allow_plaintext=False, tls_dir=tmp_path)
    assert not plan.tls


def test_non_loopback_without_tls_gets_a_generated_certificate(tmp_path):
    plan = tls.plan_listener("0.0.0.0", 8000, cert="", key="", trusted_proxies=frozenset(),
                             allow_plaintext=False, tls_dir=tmp_path)
    # LOAD-BEARING: never plain HTTP on all interfaces by default.
    assert plan.tls
    if os.name == "posix":
        assert stat.S_IMODE(Path(plan.keyfile).stat().st_mode) == 0o600
    fp = tls.fingerprint_pem(plan.certfile)
    assert len(fp.replace(":", "")) == 64
    again = tls.plan_listener("0.0.0.0", 8000, cert="", key="", trusted_proxies=frozenset(),
                              allow_plaintext=False, tls_dir=tmp_path)
    assert tls.fingerprint_pem(again.certfile) == fp  # reused, not regenerated


def test_explicit_exceptions_are_honoured(tmp_path):
    proxied = tls.plan_listener("0.0.0.0", 8000, cert="", key="",
                                trusted_proxies=frozenset({"192.0.2.1"}), allow_plaintext=False,
                                tls_dir=tmp_path)
    allowed = tls.plan_listener("0.0.0.0", 8000, cert="", key="", trusted_proxies=frozenset(),
                                allow_plaintext=True, tls_dir=tmp_path)
    assert not proxied.tls and not allowed.tls
    with pytest.raises(tls.ListenerPolicyError):
        tls.plan_listener("0.0.0.0", 8000, cert="/x.pem", key="", tls_dir=tmp_path)


def test_identity_endpoint_serves_the_fingerprint(identity_env, tmp_path, monkeypatch):
    plan = tls.plan_listener("0.0.0.0", 8000, cert="", key="", trusted_proxies=frozenset(),
                             allow_plaintext=False, tls_dir=tmp_path)
    monkeypatch.setattr(tls, "ACTIVE_FINGERPRINT", None)
    tls.activate(plan)
    assert identity_env.get("/api/server/identity").status_code == 401
    make_user("viewer.demo", role="VIEWER")
    token = login(identity_env, "viewer.demo").json()["access_token"]
    body = identity_env.get("/api/server/identity", headers=bearer(token)).json()
    assert body == {"tls": True, "cert_sha256": tls.fingerprint_pem(plan.certfile)}


@pytest.fixture
def https_server(tmp_path):
    plan = tls.plan_listener("0.0.0.0", 0, cert="", key="", trusted_proxies=frozenset(),
                             allow_plaintext=False, tls_dir=tmp_path)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(plan.certfile, plan.keyfile)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"https://127.0.0.1:{httpd.server_address[1]}/", tls.fingerprint_pem(plan.certfile)
    httpd.shutdown()


def test_agent_accepts_the_pinned_self_signed_server(https_server):
    url, fp = https_server
    opener = linux_agent.build_opener(fp)
    with opener.open(url, timeout=5) as r:
        assert r.read() == b"ok"


def test_agent_refuses_a_server_with_another_certificate(https_server):
    url, _ = https_server
    opener = linux_agent.build_opener("ab" * 32)
    with pytest.raises(Exception, match="fingerprint"):
        opener.open(url, timeout=5)


def test_agent_refuses_plain_http_while_pinned():
    opener = linux_agent.build_opener("ab" * 32)
    with pytest.raises(Exception, match="refused"):
        opener.open("http://127.0.0.1:9/", timeout=2)
