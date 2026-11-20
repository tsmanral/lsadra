"""Security regression: log forging and an API key stored in clear text.

Attacker story 1 (log forging): a device chooses its own hostname at
registration, and parsed raw lines decide the per-source counts that the
ingest endpoint logs. A value carrying CR/LF would write a second, fake line
into the server log, which an operator could take for a real entry.

Attacker story 2 (key at rest): the Windows simulator wrote the device API key
into ``agent_config.yml`` in the working directory, where any local user or
backup could read it.

Secure behaviour under test:
  * ``log_safe`` turns line breaks and control characters into visible escapes
    and caps the length.
  * A registration with a CR/LF hostname logs exactly one line.
  * The agent takes its key from ``LSADRA_AGENT_API_KEY``, and the simulator's
    config template no longer contains the key.

These fail on the old code: there was no ``log_safe``, the hostname was logged
raw, the agent ignored the environment, and the template held ``api_key:``.
SYNTHETIC data only.
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest

import lsadra.endpoint_agent.linux_agent as agent
from lsadra.security.log_safety import log_safe
from tests.fixtures import setup_test_db

ROOT = Path(__file__).resolve().parents[2]
FORGED = "demo-host-01\r\n2026-11-20 00:00:00 INFO forged entry"


# ── log_safe ──────────────────────────────────────────────────────────────


def test_log_safe_escapes_line_breaks():
    out = log_safe(FORGED)
    assert "\n" not in out and "\r" not in out
    assert "demo-host-01\\r\\n2026-11-20" in out


def test_log_safe_escapes_other_control_characters():
    out = log_safe("a\x1b[31mred\x00b\tc\x7f")
    assert out == "a\\x1b[31mred\\x00b\\x09c\\x7f"


def test_log_safe_caps_length_and_handles_non_strings():
    assert log_safe("x" * 500, 10) == "x" * 10 + "..."
    assert log_safe({"syslog\n": 2}) == "{'syslog\\n': 2}"


# ── device registration logs one line whatever the hostname ───────────────


def test_registration_with_crlf_hostname_logs_one_line(tmp_path, caplog):
    setup_test_db(tmp_path)
    from lsadra.storage.database import create_user, store_token
    from server import app

    create_user("u-log", "log.demo", "hash", "ANALYST")
    store_token("demo-log-token-not-a-secret", "u-log", datetime.utcnow() + timedelta(hours=1))
    body = {"token": "demo-log-token-not-a-secret", "hostname": FORGED, "os_type": "linux"}

    async def scenario():
        transport = httpx.ASGITransport(app=app, client=("198.51.100.91", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://lsadra.test") as c:
            return await c.post("/api/devices/register", json=body)

    with caplog.at_level(logging.INFO, logger="lsadra.onboarding.device_registration"):
        resp = asyncio.run(scenario())

    assert resp.status_code == 200, resp.text
    lines = [r.getMessage() for r in caplog.records if "Device registered" in r.getMessage()]
    assert len(lines) == 1
    assert "\n" not in lines[0] and "\r" not in lines[0]


# ── the API key stays out of files on disk ────────────────────────────────


def test_agent_reads_api_key_from_environment(tmp_path, monkeypatch):
    cfg_file = tmp_path / "agent_config.yml"
    cfg_file.write_text('device_id: "demo-device-01"\n')
    monkeypatch.setenv(agent.AGENT_API_KEY_ENV, "demo-key-not-a-secret")
    cfg = agent.load_config(str(cfg_file))
    assert cfg["api_key"] == "demo-key-not-a-secret"
    assert cfg["device_id"] == "demo-device-01"


def test_agent_without_environment_key_keeps_config_behaviour(tmp_path, monkeypatch):
    monkeypatch.delenv(agent.AGENT_API_KEY_ENV, raising=False)
    cfg_file = tmp_path / "agent_config.yml"
    cfg_file.write_text('api_key: "demo-file-key-not-a-secret"\n')
    assert agent.load_config(str(cfg_file))["api_key"] == "demo-file-key-not-a-secret"
    assert agent.load_config(str(tmp_path / "missing.yml"))["api_key"] == ""


def test_windows_simulator_does_not_write_the_key_to_its_config():
    source = (ROOT / "windows_agent_simulator.py").read_text(encoding="utf-8")
    template = re.search(r'config_yaml = f"""(.*?)"""', source, re.S)
    assert template, "simulator config template not found"
    assert "api_key" not in template.group(1)
    assert "LSADRA_AGENT_API_KEY" in source


@pytest.fixture(autouse=True)
def _no_inherited_key(monkeypatch):
    monkeypatch.delenv("LSADRA_AGENT_API_KEY", raising=False)
