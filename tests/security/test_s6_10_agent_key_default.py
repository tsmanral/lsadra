"""Security regression — §6 #10: Hardcoded agent API key default.

Attacker story: shipping a default "DEV_KEY_UNSECURE" agent API key means
every unconfigured deployment shares one publicly-known credential, so anyone
can authenticate as any endpoint agent to the collector.

Secure behavior under test:
  * DEFAULT_CONFIG["api_key"] is the empty string (NOT "DEV_KEY_UNSECURE" and
    NOT any other baked-in secret), so an unconfigured install has no usable
    credential.
  * The agent's startup guard in main() refuses to run (SystemExit code 1)
    when api_key is empty/unconfigured, instead of silently starting with a
    shared default key.

These assertions FAIL on the pre-fix code path (default key
"DEV_KEY_UNSECURE"), which is truthy and would sail past the guard.

Synthetic data only — no real credentials are used anywhere in this file.
"""

import pytest

import lsadra.endpoint_agent.linux_agent as agent


# Obviously-fake stand-ins used only to prove the guard keys off api_key.
FAKE_DEVICE_ID = "test-device-001"
FAKE_API_KEY = "test-secret-abc123"


# ── The insecure default that must never ship again ───────────────────────


def test_default_api_key_is_empty_not_dev_key():
    """The baked-in default must be empty, never the shared 'DEV_KEY_UNSECURE'."""
    assert agent.DEFAULT_CONFIG["api_key"] == ""
    assert agent.DEFAULT_CONFIG["api_key"] != "DEV_KEY_UNSECURE"
    # No non-empty literal secret of any kind survives as the default.
    assert not agent.DEFAULT_CONFIG["api_key"]


def test_load_config_missing_file_yields_empty_api_key():
    """Loading a non-existent config falls back to defaults with no credential."""
    cfg = agent.load_config("/nonexistent/lsadra-agent/config.yml")
    assert cfg["api_key"] == ""
    assert cfg["api_key"] != "DEV_KEY_UNSECURE"


# ── The startup guard must fail-closed on an unconfigured key ──────────────


def test_main_refuses_to_start_when_api_key_empty(monkeypatch):
    """main() exits(1) when api_key is unconfigured, even with a valid device_id.

    device_id is set to a truthy fake value so the guard can ONLY be tripping
    on the empty api_key — proving the credential check, not a missing host.
    """
    monkeypatch.setattr(
        agent,
        "load_config",
        lambda _p: {**agent.DEFAULT_CONFIG, "device_id": FAKE_DEVICE_ID, "api_key": ""},
    )
    monkeypatch.setattr(agent.sys, "argv", ["prog", "--config", "/nonexistent.yml"])

    with pytest.raises(SystemExit) as exc_info:
        agent.main()

    assert exc_info.value.code == 1


def test_default_config_would_refuse_to_start(monkeypatch):
    """With the shipped DEFAULT_CONFIG (empty api_key), main() must exit(1).

    This is the end-to-end proof that an unconfigured install cannot run:
    load_config for a missing path returns DEFAULT_CONFIG.copy(), whose
    api_key is '' — so the guard fires before any tailer/network work.
    """
    monkeypatch.setattr(agent, "load_config", lambda _p: {**agent.DEFAULT_CONFIG})
    monkeypatch.setattr(agent.sys, "argv", ["prog", "--config", "/nonexistent.yml"])

    with pytest.raises(SystemExit) as exc_info:
        agent.main()

    assert exc_info.value.code == 1


def test_main_starts_past_guard_when_api_key_configured(monkeypatch):
    """A properly configured (fake) api_key must clear the credential guard.

    Confirms the guard rejects specifically the *empty* key rather than always
    exiting: with a non-empty synthetic key + device_id, execution proceeds
    past the guard. We stub the tailers so no file/network work happens, and
    assert one of them was reached (i.e. we did NOT SystemExit at the guard).
    """
    reached = {"tail": False}

    monkeypatch.setattr(
        agent,
        "load_config",
        lambda _p: {
            **agent.DEFAULT_CONFIG,
            "device_id": FAKE_DEVICE_ID,
            "api_key": FAKE_API_KEY,
        },
    )
    monkeypatch.setattr(agent.sys, "argv", ["prog", "--config", "/nonexistent.yml"])

    def _fake_tail(*_args, **_kwargs):
        reached["tail"] = True

    # Stub both possible sinks so main() returns immediately after the guard.
    monkeypatch.setattr(agent, "_tail", _fake_tail)
    monkeypatch.setattr(agent, "_tail_journal", _fake_tail)

    agent.main()  # must NOT raise SystemExit

    assert reached["tail"] is True
