"""
G-7 — No legacy Streamlit dashboard.

Attacker story: `docker compose up` also started the legacy Streamlit UI on
every interface, a second login surface with its own register and login code
that the API's hardening does not cover. G-7 first made it opt-in; M3 removes
it, so the React dashboard (and the desktop app around it) is the only UI and
the API is its only login surface.

Secure behavior pinned here: no compose service runs Streamlit, the image does
not expose its port, the Streamlit code and lock are gone, and no
hash-locked requirement file installs it. Every published port still binds the
host's loopback.
"""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.override.yml")


def _compose(name):
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))["services"]


def test_no_compose_service_runs_streamlit():
    for name in COMPOSE_FILES:
        for svc_name, svc in _compose(name).items():
            text = yaml.safe_dump(svc).lower()
            assert "streamlit" not in text, f"{name}: {svc_name} runs Streamlit"
            assert "8501" not in text, f"{name}: {svc_name} uses the Streamlit port"


def test_image_does_not_expose_streamlit_port():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    expose = [ln for ln in dockerfile.splitlines() if ln.strip().upper().startswith("EXPOSE")]
    assert expose, "Dockerfile should expose the API port"
    assert all("8501" not in ln for ln in expose), expose


def test_streamlit_code_and_lock_are_gone():
    assert not (ROOT / "lsadra" / "ui" / "dashboard.py").exists()
    assert not (ROOT / "lsadra" / "ui" / "pages").exists()
    assert not (ROOT / "requirements" / "ui.in").exists()
    assert not (ROOT / "requirements" / "ui.txt").exists()


def test_no_requirement_file_installs_streamlit():
    for path in (ROOT / "requirements").glob("*.txt"):
        names = {
            ln.split("==")[0].strip().lower()
            for ln in path.read_text(encoding="utf-8").splitlines()
            if "==" in ln and not ln.lstrip().startswith("#")
        }
        assert "streamlit" not in names, f"{path.name} installs Streamlit"


def test_published_ports_bind_loopback_only():
    for name, svc in _compose("docker-compose.yml").items():
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name} publishes {port} on all interfaces"
