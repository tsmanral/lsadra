"""
Per-rule tests and metadata checks for the detection rule registry (audit G-14).

Every rule the orchestrator runs is in ``RULES``. Each event rule must have at
least one positive and one negative case below; ``test_every_rule_has_cases``
fails when a new rule arrives without them.
"""

import re

import pytest

from lsadra.detection.event_types import EVENT_TYPES
from lsadra.detection.rule_engine import (
    ALERT_LEVEL,
    LEVELS,
    RULES,
    STATUSES,
    best_match,
    evaluate,
    level_rank,
)


def row(**kw):
    base = {"source_ip": "192.0.2.10", "device_id": "dev-demo"}
    base.update(kw)
    if "event_type" in base and "canonical_event_type" not in base:
        base["canonical_event_type"] = base["event_type"]
    return base


# rule id -> (positive rows, negative rows)
CASES = {
    "lsadra-auth-credential-stuffing": (
        [row(event_type="auth_failure", failures_15m=12, unique_users_15m=6)],
        [
            row(event_type="auth_failure", failures_15m=12, unique_users_15m=2),
            row(event_type="auth_success", failures_15m=12, unique_users_15m=6),
            row(event_type="auth_failure", failures_15m=3, unique_users_15m=6),
        ],
    ),
    "lsadra-auth-brute-force": (
        [
            row(event_type="auth_failure", failures_15m=9),
            row(event_type="auth_failure", failed_logins_last_5min=6, failures_15m=6),
            row(event_type="auth_failure", failed_logins_last_5min=20, failures_15m=20),
        ],
        [
            row(event_type="auth_failure", failures_15m=3, failed_logins_last_5min=3),
            row(event_type="process_exec", failures_15m=30, failed_logins_last_5min=30),
        ],
    ),
    "lsadra-auth-low-and-slow": (
        [
            row(
                event_type="auth_failure",
                failures_15m=7,
                failure_ratio_15m=1.0,
                login_attempts_last_5min=2,
            )
        ],
        [
            row(
                event_type="auth_failure",
                failures_15m=7,
                failure_ratio_15m=0.5,
                login_attempts_last_5min=2,
            ),
            row(
                event_type="auth_failure",
                failures_15m=7,
                failure_ratio_15m=1.0,
                login_attempts_last_5min=6,
            ),
            row(event_type="auth_failure", failures_15m=40, failure_ratio_15m=1.0),
        ],
    ),
    "lsadra-auth-success-after-failures": (
        [row(event_type="auth_success", failures_15m=6, successes_15m=1)],
        [
            row(event_type="auth_success", failures_15m=1, successes_15m=1),
            row(event_type="auth_failure", failures_15m=6),
        ],
    ),
    "lsadra-auth-off-hours-access": (
        [row(event_type="auth_success", successes_15m=1, is_off_hours=1, failures_15m=0)],
        [
            row(event_type="auth_success", successes_15m=1, is_off_hours=0),
            row(event_type="process_exec", successes_15m=1, is_off_hours=1),
        ],
    ),
    "lsadra-net-port-scan": (
        [
            row(event_type="network_flow", unique_dst_ports_10min=20),
            row(event_type="firewall_deny", unique_dst_ports_10min=80),
        ],
        [
            row(event_type="network_flow", unique_dst_ports_10min=4),
            row(event_type="auth_failure", unique_dst_ports_10min=80),
        ],
    ),
    "lsadra-net-large-outbound-transfer": (
        [row(event_type="network_flow", bytes_out_to_dest_30min=50e6, dest_ip="203.0.113.9")],
        [
            row(event_type="network_flow", bytes_out_to_dest_30min=2e6),
            row(event_type="file_access", bytes_out_to_dest_30min=50e6),
        ],
    ),
    "lsadra-file-hidden-staging-dir": (
        [row(event_type="process_exec", artifact_path="/var/tmp/.stage", artifact_in_hidden_dir=1)],
        [
            row(
                event_type="process_exec",
                artifact_path="/home/bob.demo/.cache/x",
                artifact_in_hidden_dir=1,
            ),
            row(
                event_type="process_exec", artifact_path="/var/tmp/stage", artifact_in_hidden_dir=0
            ),
        ],
    ),
    "lsadra-proc-encoded-powershell": (
        [row(event_type="process_exec", encoded_command=1)],
        [
            row(event_type="process_exec", encoded_command=0),
            row(event_type="network_flow", encoded_command=1),
        ],
    ),
    "lsadra-proc-lolbin-proxy-execution": (
        [
            row(event_type="process_exec", known_lolbin=1, suspicious_cmdline=1),
            row(event_type="process_exec", known_lolbin=1, unusual_parent=1),
        ],
        [
            row(event_type="process_exec", known_lolbin=0, suspicious_cmdline=1),
            row(event_type="network_flow", known_lolbin=1, suspicious_cmdline=1),
        ],
    ),
    "lsadra-proc-suspicious-cmdline": (
        [row(event_type="process_exec", suspicious_cmdline=1)],
        [row(event_type="process_exec", suspicious_cmdline=0)],
    ),
    "lsadra-persist-service-install": (
        [
            row(
                event_type="service_install",
                artifact_path="C:\\Windows\\Temp\\x.exe",
                artifact_in_user_writable_dir=1,
                windows_artifact=1,
            ),
            row(event_type="service_install", artifact_path="/usr/lib/systemd/x.service"),
        ],
        [row(event_type="service_start"), row(event_type="registry_set")],
    ),
    "lsadra-persist-service-registry": (
        [row(event_type="registry_set", registry_service_key=1)],
        [row(event_type="registry_set", registry_service_key=0)],
    ),
    "lsadra-persist-registry-run-key": (
        [row(event_type="registry_set", registry_autostart_key=1)],
        [row(event_type="registry_set", registry_autostart_key=0)],
    ),
    "lsadra-persist-scheduled-task": (
        [row(event_type="scheduled_task_create")],
        [row(event_type="cron_job")],
    ),
    "lsadra-persist-cron-modified": (
        [row(event_type="cron_modified")],
        [row(event_type="cron_job")],
    ),
    "lsadra-persist-local-account-created": (
        [row(event_type="account_create")],
        [row(event_type="auth_success")],
    ),
    "lsadra-impair-event-log-cleared": (
        [row(event_type="log_cleared")],
        [row(event_type="log_forward")],
    ),
}

EVENT_RULES = sorted(rid for rid, r in RULES.items() if r.evaluated_by == "event")


def test_every_rule_has_cases():
    assert sorted(CASES) == EVENT_RULES
    for rid, (pos, neg) in CASES.items():
        assert pos and neg, rid


@pytest.mark.parametrize("rule_id", EVENT_RULES)
def test_rule_fires_on_positive_cases(rule_id):
    for case in CASES[rule_id][0]:
        assert rule_id in [m.rule.id for m in evaluate(case)], case


@pytest.mark.parametrize("rule_id", EVENT_RULES)
def test_rule_stays_quiet_on_negative_cases(rule_id):
    for case in CASES[rule_id][1]:
        assert rule_id not in [m.rule.id for m in evaluate(case)], case


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_metadata(rule_id):
    r = RULES[rule_id]
    assert re.fullmatch(r"lsadra-[a-z]+-[a-z0-9-]+", r.id)
    assert r.title and r.description and r.falsepositives
    assert r.version >= 1 and r.status in STATUSES and r.level in LEVELS
    assert 0.0 < r.confidence <= 1.0
    assert r.technique_ids
    assert set(r.event_types) <= set(EVENT_TYPES)
    assert r.evaluated_by in ("event", "scheduler")
    if r.evaluated_by == "event":
        assert r.matcher is not None and r.event_types


def test_levels_and_alerting():
    brute = best_match(row(event_type="auth_failure", failed_logins_last_5min=20, failures_15m=20))
    assert brute.level == "critical" and brute.severity == "CRITICAL" and brute.raises_alert
    off_hours = best_match(row(event_type="auth_success", successes_15m=1, is_off_hours=1))
    assert off_hours.level == "low" and not off_hours.raises_alert
    assert level_rank(ALERT_LEVEL) == level_rank("medium")


def test_best_match_prefers_higher_level():
    m = evaluate(row(event_type="auth_failure", failures_15m=20, unique_users_15m=8))
    assert [x.rule.id for x in m][:2] == [
        "lsadra-auth-credential-stuffing",
        "lsadra-auth-brute-force",
    ]


def test_cross_source_activity_raises_one_level():
    plain = best_match(row(event_type="scheduled_task_create"))
    raised = best_match(row(event_type="scheduled_task_create", cross_source_activity=1))
    assert level_rank(raised.level) == level_rank(plain.level) + 1
    assert "another log source" in raised.reason


def test_service_install_picks_windows_or_systemd_technique():
    win = best_match(row(event_type="service_install", windows_artifact=1))
    linux = best_match(row(event_type="service_install", windows_artifact=0))
    assert win.technique.id == "T1543.003" and linux.technique.id == "T1543.002"


def test_alert_dict_carries_rule_attribution():
    alert = best_match(row(event_type="cron_modified")).as_alert()
    assert alert["rule_id"] == "lsadra-persist-cron-modified"
    assert alert["mitre_id"] == "T1053.003" and "Persistence" in alert["mitre_tactics"]
    assert alert["rule_weight"] == RULES["lsadra-persist-cron-modified"].confidence


def test_removed_demo_rules_stay_removed():
    """A single sudo or one failed SSH password is not an alert on its own."""
    assert best_match(row(event_type="sudo_exec")) is None
    assert best_match(row(event_type="sudo_command")) is None
    one_failure = best_match(
        row(event_type="ssh_failed_password", canonical_event_type="auth_failure", failures_15m=1)
    )
    assert one_failure is None


def test_a_broken_matcher_does_not_stop_the_others(monkeypatch):
    from dataclasses import replace

    from lsadra.detection import rule_engine

    def boom(_row):
        raise RuntimeError("bad rule")

    rid = "lsadra-persist-cron-modified"
    monkeypatch.setitem(rule_engine.RULES, rid, replace(RULES[rid], matcher=boom))
    m = evaluate(row(event_type="scheduled_task_create"))
    assert [x.rule.id for x in m] == ["lsadra-persist-scheduled-task"]
