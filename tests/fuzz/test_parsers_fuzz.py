"""Property-based fuzzing of every log parser (gap G-24).

Log lines are attacker-controlled input. Every parser must, for any string:

* never raise: it returns a well-formed event or ``None``;
* when it returns an event, include every field of the unified schema with the
  right basic types, so nothing downstream trips over a half-built event;
* finish quickly (no pathological regex backtracking on long lines).

Inputs come from three generators: arbitrary Unicode text, decoded random
bytes, and synthetic seed lines from ``fuzz/seeds.py`` with random edits
(inserted delimiters, deletions, truncation, repeated chunks). The same seeds
feed the Atheris target in ``fuzz/`` that ClusterFuzzLite runs on pull requests.
"""

import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lsadra.ingestion.base_parser import REQUIRED_SCHEMA_FIELDS
from lsadra.ingestion.endpoint_parser import EndpointParser
from lsadra.ingestion.ingestion_manager import IngestionManager, _SSHParserAdapter
from lsadra.ingestion.network_flow_parser import NetworkFlowParser
from lsadra.ingestion.parsers_linux import LinuxSSHParser
from lsadra.ingestion.parsers_windows import WindowsLogonParser
from lsadra.ingestion.syslog_parser import SyslogParser
from lsadra.ingestion.windows_event_parser import WindowsEventParser
from fuzz.seeds import (
    ALL_SEEDS,
    ENDPOINT_SEEDS,
    NETWORK_SEEDS,
    SSH_SEEDS,
    SYSLOG_SEEDS,
    WINDOWS_SEEDS,
)

DEVICE = "fuzz-device.demo"
# Generous per-line budget: a parser that needs longer than this on a line of a
# few KB is backtracking, not parsing.
MAX_SECONDS_PER_LINE = 2.0

FUZZ = settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

V4_PARSERS = {
    "syslog": (SyslogParser, SYSLOG_SEEDS),
    "windows": (WindowsEventParser, WINDOWS_SEEDS),
    "network": (NetworkFlowParser, NETWORK_SEEDS),
    "endpoint": (EndpointParser, ENDPOINT_SEEDS),
    "ssh": (_SSHParserAdapter, SSH_SEEDS),
}

# Characters that matter to the parsers' formats, weighted in so random edits
# hit delimiters and markup rather than only letters.
_SPECIAL = st.sampled_from(
    list("|,:;[]{}<>\"'=/\\ \t\r\n\x00") + ["->", "SRC=", "DST=", "DPT=", "SPT=", "COMMAND="]
)
_FRAGMENT = st.one_of(_SPECIAL, st.text(max_size=12), st.integers().map(str))


@st.composite
def _mutated(draw, seeds):
    """A seed line with a few random insertions, deletions and replacements."""
    line = draw(st.sampled_from(seeds))
    for _ in range(draw(st.integers(min_value=1, max_value=6))):
        op = draw(st.sampled_from(["insert", "delete", "replace", "truncate", "repeat"]))
        pos = draw(st.integers(min_value=0, max_value=len(line)))
        if op == "insert":
            line = line[:pos] + draw(_FRAGMENT) + line[pos:]
        elif op == "delete":
            end = draw(st.integers(min_value=pos, max_value=min(len(line), pos + 8)))
            line = line[:pos] + line[end:]
        elif op == "replace":
            end = draw(st.integers(min_value=pos, max_value=min(len(line), pos + 8)))
            line = line[:pos] + draw(_FRAGMENT) + line[end:]
        elif op == "truncate":
            line = line[:pos]
        else:
            chunk = line[pos : pos + 16]
            line = line[:pos] + chunk * draw(st.integers(min_value=2, max_value=200)) + line[pos:]
    return line


def _any_line(seeds):
    return st.one_of(
        st.text(max_size=400),
        st.binary(max_size=400).map(lambda b: b.decode("utf-8", "replace")),
        _mutated(seeds),
    )


def _check_event(event):
    assert isinstance(event, dict)
    missing = [f for f in REQUIRED_SCHEMA_FIELDS if f not in event]
    assert not missing, f"event missing fields: {missing}"
    assert isinstance(event["timestamp"], str) and event["timestamp"]
    assert isinstance(event["source_type"], str)
    assert isinstance(event["event_type"], str)
    assert isinstance(event["success"], bool)
    assert isinstance(event["raw"], str)
    assert isinstance(event["extra"], dict)
    for field in ("source_ip", "dest_ip", "username"):
        assert event[field] is None or isinstance(event[field], str), field


def _timed(fn, *args):
    start = time.perf_counter()
    result = fn(*args)
    elapsed = time.perf_counter() - start
    assert elapsed < MAX_SECONDS_PER_LINE, f"took {elapsed:.2f}s on a {len(args[0])}-char line"
    return result


@pytest.mark.parametrize("name", sorted(V4_PARSERS))
def test_seed_lines_parse(name):
    # Sanity: the seeds really exercise each parser's happy path.
    cls, seeds = V4_PARSERS[name]
    parser = cls()
    parsed = [parser.parse(s, DEVICE) for s in seeds if parser.can_parse(s)]
    assert any(e is not None for e in parsed), f"no {name} seed parsed"
    for event in parsed:
        if event is not None:
            _check_event(event)


@pytest.mark.parametrize("name", sorted(V4_PARSERS))
def test_v4_parser_never_raises_and_emits_valid_events(name):
    cls, seeds = V4_PARSERS[name]
    parser = cls()

    @FUZZ
    @given(_any_line(seeds))
    def run(line):
        if _timed(parser.can_parse, line):
            event = _timed(parser.parse, line, DEVICE)
            if event is not None:
                _check_event(event)
        # parse() is also reachable without can_parse() (hinted ingestion).
        event = _timed(parser.parse, line, DEVICE)
        if event is not None:
            _check_event(event)

    run()


@FUZZ
@given(_any_line(SSH_SEEDS + SYSLOG_SEEDS))
def test_linux_ssh_parser_never_raises(line):
    event = _timed(LinuxSSHParser.parse, line, DEVICE)
    assert event is None or isinstance(event, dict)


@FUZZ
@given(_any_line(WINDOWS_SEEDS))
def test_windows_logon_parser_never_raises(line):
    event = _timed(WindowsLogonParser.parse, line, DEVICE)
    assert event is None or isinstance(event, dict)


@FUZZ
@given(_any_line(ALL_SEEDS), st.sampled_from([None, "ssh", "syslog", "windows", "network", "endpoint", "bogus"]))
def test_ingestion_manager_never_raises(line, hint):
    manager = IngestionManager()
    event = _timed(manager.ingest_line, line, DEVICE, hint)
    if event is not None:
        _check_event(event)
    # A parser exception is swallowed and counted; the fuzz contract is that
    # none happen at all.
    stats = manager.get_source_stats()
    errors = sum(
        v.get("errors", 0) if isinstance(v, dict) else 0
        for v in (stats.values() if isinstance(stats, dict) else [])
    )
    assert errors == 0, f"a parser raised on {line!r}: {stats}"
