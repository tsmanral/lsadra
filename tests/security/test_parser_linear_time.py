"""Regression: log parsers stay fast on long, attacker-shaped lines.

Log lines are attacker-controlled. A device may send raw lines up to
MAX_RAW_MESSAGE_LENGTH characters, and every one of them goes through the
parser chain on the ingest path. Patterns with several unbounded gaps can
backtrack super-linearly on crafted input, letting one batch pin a server
thread for minutes. Found by the parser fuzz tests (tests/fuzz/).

Each case below is a line built to maximise backtracking for one parser. On the
old patterns the slowest took about a second at this length (and grew roughly
eightfold for every doubling); every parser must now finish well inside the
budget.
"""

import time

import pytest

from lsadra.config import MAX_RAW_MESSAGE_LENGTH
from lsadra.endpoint_agent import linux_agent
from lsadra.ingestion.endpoint_parser import EndpointParser
from lsadra.ingestion.ingestion_manager import IngestionManager
from lsadra.ingestion.network_flow_parser import NetworkFlowParser
from lsadra.ingestion.parsers_linux import LinuxSSHParser
from lsadra.ingestion.syslog_parser import SyslogParser

# A line this long takes well under 10 ms to parse on a linear pattern; the
# budget leaves room for slow CI runners while catching any super-linear one.
BUDGET_SECONDS = 0.25
SSH_PREFIX = "Jan  5 12:35:00 host1.demo sshd[1234]: "
SYSLOG_PREFIX = "Mar 10 08:00:01 host2.demo app[1]: "


def _fill(prefix, unit):
    n = (MAX_RAW_MESSAGE_LENGTH - len(prefix)) // len(unit)
    return prefix + unit * n


CASES = {
    "ssh-colon-run": (LinuxSSHParser.parse, _fill(SSH_PREFIX, "::")),
    "ssh-pam-run": (LinuxSSHParser.parse, _fill(SSH_PREFIX, "pam_unix(sshd:se")),
    "syslog-cron-run": (lambda s: SyslogParser().parse(s, "d"), _fill(SYSLOG_PREFIX, "]CRON[")),
    "syslog-su-run": (lambda s: SyslogParser().parse(s, "d"), _fill(SYSLOG_PREFIX, "su[]")),
    "syslog-sudo-run": (lambda s: SyslogParser().parse(s, "d"), _fill(SYSLOG_PREFIX, "sudo")),
    "firewall-run": (lambda s: NetworkFlowParser().parse(s, "d"), _fill("", "SRC=1.1DST=1.1")),
    "endpoint-run": (lambda s: EndpointParser().parse(s, "d"), _fill("", "cmd.exe/tmp/|")),
    "manager-auto": (
        lambda s: IngestionManager().ingest_line(s, "d"),
        _fill(SSH_PREFIX, "::"),
    ),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_parser_finishes_within_budget_on_crafted_line(case):
    parse, line = CASES[case]
    assert len(line) <= MAX_RAW_MESSAGE_LENGTH
    start = time.perf_counter()
    parse(line)
    elapsed = time.perf_counter() - start
    assert elapsed < BUDGET_SECONDS, f"{case}: {elapsed:.3f}s on a {len(line)}-char line"


def test_agent_sudo_pattern_is_linear():
    # The Linux agent reads local auth logs with the same sudo pattern; a local
    # user who can write to them must not be able to stall the agent.
    message = ":" * MAX_RAW_MESSAGE_LENGTH
    start = time.perf_counter()
    linux_agent._SUDO_RE.match(message)
    assert time.perf_counter() - start < BUDGET_SECONDS


@pytest.mark.parametrize(
    "line, user, command",
    [
        (
            SSH_PREFIX.replace("sshd", "sudo") + "alice.demo : TTY=pts/0 ; COMMAND=/bin/ls -la",
            "alice.demo",
            "/bin/ls -la",
        ),
        (
            SSH_PREFIX.replace("sshd", "sudo") + "  bob.demo: PWD=/ ; COMMAND=/usr/bin/id",
            "bob.demo",
            "/usr/bin/id",
        ),
    ],
)
def test_ssh_parser_still_reads_sudo_lines(line, user, command):
    event = LinuxSSHParser.parse(line)
    assert event["event_type"] == "sudo_exec"
    assert event["effective_username"] == user
    assert event["attributes"]["command"] == command


def test_syslog_matchers_keep_their_results():
    from lsadra.ingestion import syslog_parser as sp

    assert sp._match_cron("CRON[2001]: (root) CMD (run-parts [x] /etc/cron.hourly)") == (
        "run-parts [x] /etc/cron.hourly"
    )
    assert sp._match_cron("CRON[2001]: (root) no command here") is None
    assert (
        sp._match_failed_su("su[3003]: FAILED SU (to root) for carol.demo on pts/1") == "carol.demo"
    )
    assert sp._match_failed_su("su[3003]: session opened for carol.demo") is None
    assert sp._match_sudo("sudo: carol.demo : TTY=pts/1 ; COMMAND=/bin/true") == "/bin/true"
    assert sp._match_sudo("COMMAND=/bin/true sudo") is None


def test_firewall_lines_still_parse():
    fw = NetworkFlowParser().parse(
        "Mar 10 08:00:02 fw1.demo kernel: IN=eth0 SRC=203.0.113.5 DST=192.0.2.30 PROTO=TCP SPT=40000 DPT=3389",
        "d",
    )
    assert fw["source_ip"] == "203.0.113.5"
    assert fw["dest_ip"] == "192.0.2.30"
    assert fw["extra"]["dst_port"] == 3389
