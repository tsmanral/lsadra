"""
Contract: one closed list of event types, mapped to OCSF and ECS (audit G-15).

Producers in this repo (parsers, agents, the demo corpus) emit canonical names;
older names resolve through aliases; everything else is ``other``; and no rule
keys on a name outside the list.
"""

import json
from pathlib import Path

import pytest

from lsadra.detection.event_types import (
    ALIASES,
    EVENT_TYPES,
    OTHER,
    canonical_event_type,
    is_failure,
    is_success,
)
from lsadra.detection.rule_engine import RULES

REPO = Path(__file__).resolve().parent.parent

# OCSF 1.9 classes the list may use (uid -> name); 0 is the Base Event.
OCSF_CLASSES = {
    0: "Base Event",
    1001: "File System Activity",
    1005: "Module Activity",
    1006: "Scheduled Job Activity",
    1007: "Process Activity",
    1008: "Event Log Activity",
    1009: "Script Activity",
    3001: "Account Change",
    3002: "Authentication",
    3006: "Group Management",
    4001: "Network Activity",
    4003: "DNS Activity",
    5019: "Device Config State Change",
    201002: "Registry Value Activity",
    201004: "Windows Service Activity",
}
# ECS 9.x allowed values for event.category and event.type.
ECS_CATEGORIES = {
    "api",
    "authentication",
    "configuration",
    "database",
    "driver",
    "email",
    "file",
    "host",
    "iam",
    "intrusion_detection",
    "library",
    "malware",
    "network",
    "package",
    "process",
    "registry",
    "session",
    "threat",
    "vulnerability",
    "web",
}
ECS_TYPES = {
    "access",
    "admin",
    "allowed",
    "change",
    "connection",
    "creation",
    "deletion",
    "denied",
    "device",
    "end",
    "error",
    "group",
    "indicator",
    "info",
    "installation",
    "protocol",
    "start",
    "user",
}


def test_list_is_closed_and_small():
    assert 20 <= len(EVENT_TYPES) <= 35
    assert OTHER in EVENT_TYPES


@pytest.mark.parametrize("name", sorted(EVENT_TYPES))
def test_each_type_maps_to_ocsf_and_ecs(name):
    et = EVENT_TYPES[name]
    assert et.name == name and name == name.lower() and " " not in name
    assert OCSF_CLASSES.get(et.ocsf_class_uid) == et.ocsf_class_name
    assert et.ocsf_activity
    assert set(et.ecs_category) <= ECS_CATEGORIES
    assert et.ecs_type and set(et.ecs_type) <= ECS_TYPES
    assert et.source in {"auth", "endpoint", "network", "system"}
    assert et.outcome in (None, "success", "failure")
    assert et.description


def test_aliases_resolve_to_canonical_types():
    for alias, target in ALIASES.items():
        assert target in EVENT_TYPES, alias
        assert alias not in EVENT_TYPES, f"{alias} is both canonical and an alias"
        assert canonical_event_type(alias) == target


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ssh_failed_password", "auth_failure"),
        ("ssh_failed_publickey", "auth_failure"),
        ("ssh_accepted_publickey", "auth_success"),
        ("windows_logon_failure", "auth_failure"),
        ("process_create", "process_exec"),
        ("connection", "network_flow"),
        ("  AUTH_FAILURE ", "auth_failure"),
        ("syslog_event", OTHER),
        ("made_up_type", OTHER),
        (None, OTHER),
        (42, OTHER),
    ],
)
def test_canonical_event_type(raw, expected):
    assert canonical_event_type(raw) == expected


def test_outcome_dependent_alias_needs_the_outcome():
    assert canonical_event_type("login_attempt", success=True) == "auth_success"
    assert canonical_event_type("login_attempt", success=False) == "auth_failure"
    assert canonical_event_type("login_attempt") == OTHER


@pytest.mark.parametrize(
    "lookalike",
    [
        "auth​_failure",
        "auth⁧_failure⁩",
        "auth_failure\U000e0041",
        "auth_failure|---|---",
        "auth_failure\x1b[2J",
        "process_exec‮",
    ],
)
def test_lookalike_strings_do_not_resolve(lookalike):
    """Injection-corpus strings must not count as real events (or failures)."""
    assert canonical_event_type(lookalike) == OTHER
    assert not is_failure(canonical_event_type(lookalike))


def test_outcome_helpers():
    assert is_failure("auth_failure") and not is_success("auth_failure")
    assert is_success("auth_success") and not is_failure("auth_success")
    assert not is_failure("process_exec") and not is_success("process_exec")


def test_demo_corpus_uses_only_canonical_names():
    for path in sorted((REPO / "demo" / "corpus").glob("*.jsonl")):
        if path.stem == "injection_attempts":  # deliberately hostile strings
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            et = json.loads(line)["event_type"]
            assert et in EVENT_TYPES and et != OTHER, f"{path.name}: {et}"


def test_rules_key_only_on_canonical_types():
    for rule in RULES.values():
        for et in rule.event_types:
            assert et in EVENT_TYPES and et != OTHER, f"{rule.id}: {et}"


# ── in-repo producers emit canonical names ─────────────────────────────────

RAW_LINES = [
    (
        "Jan 15 02:01:12 demo-host-01 sshd[18402]: Failed password for alice.demo "
        "from 192.0.2.45 port 51422 ssh2",
        "ssh",
        "auth_failure",
    ),
    (
        "Jan 15 02:01:12 demo-host-01 sshd[18402]: Accepted publickey for alice.demo "
        "from 192.0.2.45 port 51422 ssh2",
        "ssh",
        "auth_success",
    ),
    ("4625|2026-01-15T02:01:12|bob.demo|192.0.2.4|demo-host|x", "windows", "auth_failure"),
    ("4624|2026-01-15T02:01:12|bob.demo|192.0.2.4|demo-host|x", "windows", "auth_success"),
    ("7045|2026-01-15T02:01:12|bob.demo|192.0.2.4|demo-host|x", "windows", "service_install"),
    ("4698|2026-01-15T02:01:12|bob.demo|192.0.2.4|demo-host|x", "windows", "scheduled_task_create"),
    ("4720|2026-01-15T02:01:12|bob.demo|192.0.2.4|demo-host|x", "windows", "account_create"),
    ("1102|2026-01-15T02:01:12|bob.demo|192.0.2.4|demo-host|x", "windows", "log_cleared"),
]


@pytest.mark.parametrize("line,hint,expected", RAW_LINES)
def test_ingestion_manager_emits_canonical_names(line, hint, expected):
    from lsadra.ingestion.ingestion_manager import IngestionManager

    event = IngestionManager().ingest_line(line, device_id="dev-demo", hint=hint)
    assert event is not None
    assert event["event_type"] == expected


def test_ingestion_manager_never_emits_a_non_canonical_name():
    from lsadra.ingestion.ingestion_manager import IngestionManager

    lines = [
        "<86>Jan 15 02:01:12 demo-host-01 sudo: alice.demo : TTY=pts/0 ; PWD=/ ; "
        "USER=root ; COMMAND=/usr/bin/id",
        "Jan 15 02:01:12 demo-host-01 kernel: something odd happened",
        "2026-01-15T02:01:12Z 192.0.2.4 198.51.100.7 51515 443 TCP 1200 ALLOW",
    ]
    manager = IngestionManager()
    for line in lines:
        event = manager.ingest_line(line, device_id="dev-demo")
        if event is not None:
            assert event["event_type"] in EVENT_TYPES, line


def test_v3_ssh_parser_emits_canonical_names():
    from lsadra.ingestion.parsers_linux import LinuxSSHParser

    parser = LinuxSSHParser()
    failed = parser.parse(
        "Jan 15 02:01:12 demo-host-01 sshd[1]: Failed password for bob.demo "
        "from 192.0.2.4 port 2222 ssh2",
        device_id="d",
    )
    sudo = parser.parse(
        "Jan 15 02:01:12 demo-host-01 sudo[2]: bob.demo : TTY=pts/0 ; PWD=/ ; "
        "USER=root ; COMMAND=/usr/bin/id",
        device_id="d",
    )
    assert failed["event_type"] == "auth_failure"
    assert failed["attributes"]["auth_method"] == "password"
    assert sudo["event_type"] == "sudo_exec"
