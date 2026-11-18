"""Agent posture checks: CIS IG1-tagged, read-only, contract-v1 events (G-31)."""

import json
import os
from pathlib import Path

import pytest

from lsadra.endpoint_agent import linux_agent, posture

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "docs/contracts/event-schema.v1.json").read_text(encoding="utf-8"))

# CIS Controls v8.1 Implementation Group 1 safeguards.
IG1 = {
    "1.1", "1.2", "2.1", "2.2", "2.3", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6",
    "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "5.1", "5.2", "5.3", "5.4",
    "6.1", "6.2", "6.3", "6.4", "6.5", "7.1", "7.2", "7.3", "7.4", "8.1", "8.2",
    "8.3", "9.1", "9.2", "10.1", "10.2", "10.3", "11.1", "11.2", "11.3", "11.4",
    "12.1", "14.1", "14.2", "14.3", "14.4", "14.5", "14.6", "14.7", "14.8",
    "15.1", "17.1", "17.2", "17.3",
}


def _no_commands(argv):
    return None  # every status command "not installed"


def _write(root, path, text):
    full = root / path.lstrip("/")
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(text, encoding="utf-8")
    os.chmod(full, 0o600)
    return full


# ── The shipped check file ────────────────────────────────────────────────


def test_subset_loader_reads_the_check_file_exactly_like_pyyaml():
    yaml = pytest.importorskip("yaml")
    text = Path(posture.CHECKS_FILE).read_text(encoding="utf-8")
    assert posture.load_yaml_subset(text) == yaml.safe_load(text)


def _walk(check):
    yield check
    for sub in check.get("any_of", []):
        yield from _walk(sub)


def test_shipped_checks_are_well_formed_and_ig1_tagged():
    checks = posture.load_checks()
    assert len(checks) >= 10
    ids = [c["id"] for c in checks]
    assert len(ids) == len(set(ids))
    for check in checks:
        assert check["title"]
        assert check["cis"] and set(check["cis"]) <= IG1, check["id"]
        for node in _walk(check):
            assert node["type"] in posture._TYPES, node
            if node["type"] == "command":
                assert node["argv"][0] in posture.ALLOWED_COMMANDS, node


def test_only_allow_listed_commands_run():
    status, detail = posture.evaluate({"type": "command", "argv": ["rm", "-rf", "/"], "pattern": "x"})
    assert status == posture.ERROR
    assert "not allowed" in detail


# ── sshd configuration ────────────────────────────────────────────────────


ROOT_LOGIN = {"type": "sshd_option", "key": "PermitRootLogin", "allowed": ["no", "prohibit-password"], "default": "prohibit-password"}
PASSWORD_AUTH = {"type": "sshd_option", "key": "PasswordAuthentication", "allowed": ["no"], "default": "yes"}


def test_sshd_check_is_not_applicable_without_an_ssh_server(tmp_path):
    assert posture.evaluate(ROOT_LOGIN, str(tmp_path), _no_commands)[0] == posture.NOT_APPLICABLE


def test_sshd_defaults_apply_when_the_option_is_absent(tmp_path):
    _write(tmp_path, "/etc/ssh/sshd_config", "Port 22\n")
    assert posture.evaluate(ROOT_LOGIN, str(tmp_path), _no_commands)[0] == posture.PASS
    assert posture.evaluate(PASSWORD_AUTH, str(tmp_path), _no_commands)[0] == posture.FAIL


def test_sshd_first_value_wins_and_include_files_come_first(tmp_path):
    _write(tmp_path, "/etc/ssh/sshd_config.d/50-local.conf", "PasswordAuthentication no\n")
    _write(
        tmp_path,
        "/etc/ssh/sshd_config",
        "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin=yes\n",
    )
    assert posture.evaluate(PASSWORD_AUTH, str(tmp_path), _no_commands)[0] == posture.PASS
    status, detail = posture.evaluate(ROOT_LOGIN, str(tmp_path), _no_commands)
    assert status == posture.FAIL and "yes" in detail


def test_sshd_match_blocks_do_not_count_as_global_settings(tmp_path):
    _write(tmp_path, "/etc/ssh/sshd_config", "# comment\nMatch User backup.demo\n  PasswordAuthentication no\n")
    assert posture.evaluate(PASSWORD_AUTH, str(tmp_path), _no_commands)[0] == posture.FAIL


# ── Files ─────────────────────────────────────────────────────────────────


def _shipped(check_id):
    return next(c for c in posture.load_checks() if c["id"] == check_id)


def test_extra_uid0_account_fails(tmp_path):
    check = _shipped("lnx-single-uid0")
    _write(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nalice.demo:x:1000:1000::/home/a:/bin/sh\n")
    assert posture.evaluate(check, str(tmp_path), _no_commands)[0] == posture.PASS
    _write(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/sh\ntoor.demo:x:0:0::/root:/bin/sh\n")
    assert posture.evaluate(check, str(tmp_path), _no_commands)[0] == posture.FAIL


def test_world_readable_shadow_fails(tmp_path, monkeypatch):
    # The mode is faked rather than set on disk, so the test never creates a
    # world-readable file and runs the same on every OS.
    check = _shipped("lnx-shadow-permissions")
    _write(tmp_path, "/etc/shadow", "root:*:1::::::\n")
    monkeypatch.setattr(posture, "_mode_of", lambda _path: 0o640)
    assert posture.evaluate(check, str(tmp_path), _no_commands)[0] == posture.PASS
    monkeypatch.setattr(posture, "_mode_of", lambda _path: 0o644)
    assert posture.evaluate(check, str(tmp_path), _no_commands)[0] == posture.FAIL


# ── Commands and any_of ───────────────────────────────────────────────────


def test_firewall_any_of_passes_on_one_active_firewall(tmp_path):
    check = _shipped("lnx-firewall-active")
    outputs = {("ufw", "status"): "Status: inactive\n", ("systemctl", "is-active", "firewalld"): "active\n"}
    run = lambda argv: outputs.get(tuple(argv))  # noqa: E731
    assert posture.evaluate(check, str(tmp_path), run)[0] == posture.PASS


def test_firewall_any_of_fails_when_installed_but_off(tmp_path):
    check = _shipped("lnx-firewall-active")
    run = lambda argv: "Status: inactive\n" if argv[0] == "ufw" else None  # noqa: E731
    assert posture.evaluate(check, str(tmp_path), run)[0] == posture.FAIL


def test_any_of_is_not_applicable_when_nothing_is_installed(tmp_path):
    check = _shipped("lnx-auto-updates")
    assert posture.evaluate(check, str(tmp_path), _no_commands)[0] == posture.NOT_APPLICABLE


def test_a_broken_check_reports_an_error_instead_of_raising(tmp_path):
    def boom(argv):
        raise OSError("boom")

    assert posture.evaluate(_shipped("lnx-disk-encryption"), str(tmp_path), boom)[0] == posture.ERROR
    assert posture.evaluate({"type": "nope"})[0] == posture.ERROR


# ── Read-only and contract-valid ──────────────────────────────────────────


def test_checks_never_change_the_host(tmp_path):
    _write(tmp_path, "/etc/ssh/sshd_config", "PermitRootLogin yes\n")
    _write(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n")
    _write(tmp_path, "/etc/shadow", "root:*:1::::::\n")
    before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in tmp_path.rglob("*") if p.is_file()}
    posture.run_all(root=str(tmp_path), run=_no_commands)
    after = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in tmp_path.rglob("*") if p.is_file()}
    assert before == after


def test_results_become_contract_v1_events(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    _write(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n")
    results = posture.run_all(root=str(tmp_path), run=_no_commands)
    events = posture.to_events(results, host="host1.demo")
    assert len(events) == len(results)
    validator = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())
    for event in events:
        validator.validate(event)
        assert event["event_type"] == "posture_check"
        assert event["attributes"]["status"] in {"pass", "fail", "not_applicable", "error"}


def test_core_ingest_model_accepts_posture_events(tmp_path):
    from lsadra.ingestion.api_ingestion import EventBatch

    events = posture.to_events(posture.run_all(root=str(tmp_path), run=_no_commands), host="h.demo")
    EventBatch(events=events)


# ── Agent wiring ──────────────────────────────────────────────────────────


def test_agent_skips_posture_checks_when_turned_off():
    assert linux_agent.start_posture_checks({"posture_interval_hours": "0"}) is None


def test_agent_finds_the_posture_module():
    assert linux_agent._load_posture_module() is posture
