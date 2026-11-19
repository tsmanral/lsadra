"""
G-7 — The legacy Streamlit dashboard is off by default.

Attacker story: `docker compose up` also started the legacy Streamlit UI on
every interface, a second login surface with its own register and login code
that the API's hardening does not cover.

Secure behavior pinned here: the Streamlit service runs only under the opt-in
"legacy" compose profile, and every published port binds the host's loopback.
"""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _compose(name="docker-compose.yml"):
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))["services"]


def test_streamlit_service_is_opt_in():
    services = _compose()
    assert services["dashboard"].get("profiles") == ["legacy"]
    assert _compose("docker-compose.override.yml")["dashboard"].get("profiles") == ["legacy"]


def test_published_ports_bind_loopback_only():
    for name, svc in _compose().items():
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name} publishes {port} on all interfaces"
