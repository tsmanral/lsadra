#!/usr/bin/python3
"""Atheris fuzz target for every log parser (gap G-24).

Run by ClusterFuzzLite on pull requests (.github/workflows/cflite_pr.yml). The
first input byte picks a parser, the rest is the log line. A crash is any
exception escaping a parser, or an event missing a field of the unified schema.

Local run (Linux, Python with atheris installed):
    python fuzz/fuzz_parsers.py -max_total_time=60
"""

import os
import sys

import atheris

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

with atheris.instrument_imports():
    from lsadra.ingestion.base_parser import REQUIRED_SCHEMA_FIELDS
    from lsadra.ingestion.endpoint_parser import EndpointParser
    from lsadra.ingestion.ingestion_manager import IngestionManager, _SSHParserAdapter
    from lsadra.ingestion.network_flow_parser import NetworkFlowParser
    from lsadra.ingestion.parsers_linux import LinuxSSHParser
    from lsadra.ingestion.parsers_windows import WindowsLogonParser
    from lsadra.ingestion.syslog_parser import SyslogParser
    from lsadra.ingestion.windows_event_parser import WindowsEventParser

DEVICE = "fuzz-device.demo"
V4_PARSERS = [
    SyslogParser(),
    WindowsEventParser(),
    NetworkFlowParser(),
    EndpointParser(),
    _SSHParserAdapter(),
]
MANAGER = IngestionManager()
HINTS = [None, "ssh", "syslog", "windows", "network", "endpoint"]


def _check(event):
    if event is None:
        return
    missing = [f for f in REQUIRED_SCHEMA_FIELDS if f not in event]
    if missing:
        raise AssertionError(f"event missing fields {missing}")
    if not isinstance(event["success"], bool) or not isinstance(event["extra"], dict):
        raise AssertionError("event has wrong field types")


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    selector, line = data[0], data[1:].decode("utf-8", "replace")
    choice = selector % (len(V4_PARSERS) + 3)
    if choice < len(V4_PARSERS):
        parser = V4_PARSERS[choice]
        parser.can_parse(line)
        _check(parser.parse(line, DEVICE))
    elif choice == len(V4_PARSERS):
        LinuxSSHParser.parse(line, DEVICE)
    elif choice == len(V4_PARSERS) + 1:
        WindowsLogonParser.parse(line, DEVICE)
    else:
        before = sum(v["errors"] for v in MANAGER.get_source_stats().values())
        _check(MANAGER.ingest_line(line, DEVICE, HINTS[selector % len(HINTS)]))
        after = sum(v["errors"] for v in MANAGER.get_source_stats().values())
        if after != before:
            raise AssertionError("a parser raised inside IngestionManager")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
