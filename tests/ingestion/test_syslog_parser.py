"""Fixture unit tests for SyslogParser (lsadra/ingestion/syslog_parser.py)."""

import pytest

from lsadra.ingestion.syslog_parser import SyslogParser


@pytest.fixture
def parser():
    return SyslogParser()


def test_rfc3164_header_fields(parser):
    line = "Nov 20 10:02:00 demo-host-01 systemd[1]: Started Demo Service."
    assert parser.source_type == "syslog"
    assert parser.can_parse(line) is True
    event = parser.parse(line, "dev-01")
    assert event is not None
    assert parser.validate_output(event)
    assert event["source_type"] == "syslog"
    assert event["device_id"] == "dev-01"
    assert event["timestamp"].endswith("-11-20T10:02:00")
    assert event["extra"]["host"] == "demo-host-01"
    assert event["extra"]["process_name"] == "systemd"
    assert event["extra"]["pid"] == "1"
    # RFC 3164 lines carry no <priority>, so facility and severity are unknown.
    assert event["extra"]["facility"] is None
    assert event["extra"]["severity_level"] is None


def test_rfc5424_header_fields(parser):
    line = (
        "<86>1 2026-11-20T10:06:00Z demo-host-02 sudo 1234 - - "
        "carol.demo : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls"
    )
    assert parser.can_parse(line) is True
    event = parser.parse(line, "dev-02")
    assert event is not None
    assert parser.validate_output(event)
    assert event["timestamp"] == "2026-11-20T10:06:00+00:00"
    assert event["extra"]["host"] == "demo-host-02"
    assert event["extra"]["process_name"] == "sudo"
    assert event["extra"]["pid"] == "1234"
    assert event["extra"]["facility"] == 10  # authpriv
    assert event["extra"]["severity_level"] == 6  # info
    assert event["event_type"] == "privilege_escalation"
    assert event["username"] == "carol.demo"
    assert event["extra"]["command"] == "/bin/ls"


@pytest.mark.parametrize(
    "line, event_type, success, extra",
    [
        (
            "Nov 20 10:00:00 demo-host-01 sudo: alice.demo : TTY=pts/0 ; "
            "PWD=/home/alice.demo ; USER=root ; COMMAND=/usr/bin/id",
            "privilege_escalation",
            True,
            {"command": "/usr/bin/id"},
        ),
        (
            "Nov 20 10:01:00 demo-host-01 CRON[4242]: (root) CMD (/usr/local/bin/backup.sh)",
            "cron_modified",
            True,
            {"command": "/usr/local/bin/backup.sh"},
        ),
        (
            "Nov 20 10:02:00 demo-host-01 systemd[1]: Started Demo Service.",
            "service_change",
            True,
            {"service_name": "Demo Service."},
        ),
        (
            "Nov 20 10:02:30 demo-host-01 systemd[1]: Stopped Demo Service.",
            "service_change",
            False,
            {"service_name": "Demo Service."},
        ),
        (
            "Nov 20 10:03:00 demo-host-01 kernel: [   12.345] demo_mod: module loaded",
            "kernel_module_load",
            True,
            {},
        ),
        (
            "Nov 20 10:04:00 demo-host-01 kernel: [   13.001] eth0 up",
            "network_interface_change",
            True,
            {"interface": "eth0", "state": "up"},
        ),
        (
            "Nov 20 10:05:00 demo-host-01 su[999]: FAILED SU (to root) on pts/1 for bob.demo",
            "login_attempt",
            False,
            {},
        ),
        (
            "Nov 20 10:06:00 demo-host-01 demo-app[77]: cache warmed",
            "syslog_event",
            True,
            {"message_snippet": "cache warmed"},
        ),
    ],
)
def test_message_classes(parser, line, event_type, success, extra):
    assert parser.can_parse(line) is True
    event = parser.parse(line, "dev-01")
    assert event is not None
    assert parser.validate_output(event)
    assert event["event_type"] == event_type
    assert event["success"] is success
    for key, value in extra.items():
        assert event["extra"][key] == value


def test_sudo_and_failed_su_users(parser):
    sudo = parser.parse(
        "Nov 20 10:00:00 demo-host-01 sudo: alice.demo : USER=root ; COMMAND=/usr/bin/id",
        "dev-01",
    )
    assert sudo["username"] == "alice.demo"
    su = parser.parse(
        "Nov 20 10:05:00 demo-host-01 su[999]: FAILED SU (to root) on pts/1 for bob.demo",
        "dev-01",
    )
    assert su["username"] == "bob.demo"


def test_ssh_auth_lines_are_left_to_the_ssh_parser(parser):
    line = (
        "Nov 20 10:07:00 demo-host-01 sshd[555]: Failed password for dave.demo "
        "from 192.0.2.10 port 50000 ssh2"
    )
    assert parser.can_parse(line) is False


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "not a syslog line at all",
        "2026-11-20T10:00:00Z|demo-host-01|alice.demo|bash|sshd|/tmp/x.sh||process_create",
        '{"event": "json, not syslog"}',
        "Nov 99",
        "<13>2 2026-11-20T10:00:00Z demo-host-01 app - - - wrong version",
        "x" * 100_000,
        "Nov 20 10:00:00 demo-host-01 sudo: " + "A" * 50_000,
    ],
)
def test_malformed_lines_never_raise(parser, line):
    if not parser.can_parse(line):
        return
    event = parser.parse(line, "dev-01")
    assert event is None or parser.validate_output(event)


def test_parse_returns_none_for_non_syslog(parser):
    assert parser.parse("", "dev-01") is None
    assert parser.parse("not a syslog line at all", "dev-01") is None
