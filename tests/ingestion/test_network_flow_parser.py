"""Fixture unit tests for NetworkFlowParser (lsadra/ingestion/network_flow_parser.py)."""

import pytest

from lsadra.ingestion.network_flow_parser import (
    COMMON_PORTS,
    LARGE_TRANSFER_BYTES,
    NetworkFlowParser,
)


@pytest.fixture
def parser():
    return NetworkFlowParser()


def test_netflow_csv_line(parser):
    line = "2026-11-20T10:00:00,192.0.2.10,198.51.100.20,50000,443,TCP,512,4"
    assert parser.source_type == "network_flow"
    assert parser.can_parse(line) is True
    event = parser.parse(line, "dev-01")
    assert event is not None
    assert parser.validate_output(event)
    assert event["timestamp"] == "2026-11-20T10:00:00"
    assert event["source_ip"] == "192.0.2.10"
    assert event["dest_ip"] == "198.51.100.20"
    assert event["event_type"] == "connection"
    assert event["success"] is True
    assert event["device_id"] == "dev-01"
    extra = event["extra"]
    assert extra["src_port"] == 50000
    assert extra["dst_port"] == 443
    assert extra["protocol"] == "TCP"
    assert extra["bytes"] == 512
    assert extra["large_transfer"] is False
    assert extra["unusual_port"] is False
    assert extra["internal_to_internal"] is False
    assert extra["port_scan_indicator"] is False


def test_connection_log_line(parser):
    line = "2026-11-20T10:01:00 192.0.2.11:41000 -> 203.0.113.5:22 TCP 2048"
    assert parser.can_parse(line) is True
    event = parser.parse(line, "dev-01")
    assert event is not None
    assert parser.validate_output(event)
    assert event["source_ip"] == "192.0.2.11"
    assert event["dest_ip"] == "203.0.113.5"
    assert event["event_type"] == "connection"
    assert event["extra"]["src_port"] == 41000
    assert event["extra"]["dst_port"] == 22
    assert event["extra"]["protocol"] == "TCP"
    assert event["extra"]["bytes"] == 2048


def test_connection_log_line_without_bytes(parser):
    event = parser.parse("2026-11-20T10:01:30 192.0.2.11:41001 -> 203.0.113.5:53 UDP", "d")
    assert event is not None
    assert event["extra"]["protocol"] == "UDP"
    assert event["extra"]["bytes"] == 0


def test_firewall_deny_line(parser):
    line = (
        "Nov 20 10:02:00 demo-fw-01 kernel: DENY IN=eth0 OUT= "
        "SRC=203.0.113.50 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=51515 DPT=23"
    )
    assert parser.can_parse(line) is True
    event = parser.parse(line, "dev-01")
    assert event is not None
    assert parser.validate_output(event)
    assert event["timestamp"].endswith("-11-20T10:02:00")
    assert event["source_ip"] == "203.0.113.50"
    assert event["dest_ip"] == "192.0.2.10"
    assert event["event_type"] == "firewall_deny"
    assert event["success"] is False
    assert event["extra"]["src_port"] == 51515
    assert event["extra"]["dst_port"] == 23
    assert event["extra"]["unusual_port"] is True


def test_firewall_line_without_source_port(parser):
    line = "Nov 20 10:02:30 demo-fw-01 kernel: DENY SRC=203.0.113.51 DST=192.0.2.10 DPT=3389"
    event = parser.parse(line, "dev-01")
    assert event is not None
    assert event["extra"]["src_port"] == 0
    assert event["extra"]["dst_port"] == 3389


def test_large_transfer_flag(parser):
    over = LARGE_TRANSFER_BYTES + 1
    at_limit = parser.parse(
        f"2026-11-20T10:03:00,192.0.2.10,198.51.100.20,50000,443,TCP,{LARGE_TRANSFER_BYTES},9", "d"
    )
    above = parser.parse(
        f"2026-11-20T10:03:00,192.0.2.10,198.51.100.20,50000,443,TCP,{over},9", "d"
    )
    assert at_limit["extra"]["large_transfer"] is False
    assert above["extra"]["large_transfer"] is True


def test_unusual_port_flag(parser):
    unusual = 4444
    assert unusual not in COMMON_PORTS
    event = parser.parse(
        f"2026-11-20T10:04:00,192.0.2.10,198.51.100.20,50000,{unusual},TCP,100,1", "d"
    )
    assert event["extra"]["unusual_port"] is True


def test_internal_to_internal_flag(parser):
    internal = parser.parse("2026-11-20T10:05:00,10.0.0.5,192.168.1.20,50000,445,TCP,100,1", "d")
    outbound = parser.parse("2026-11-20T10:05:00,10.0.0.5,198.51.100.20,50000,443,TCP,100,1", "d")
    assert internal["extra"]["internal_to_internal"] is True
    assert outbound["extra"]["internal_to_internal"] is False


@pytest.mark.parametrize(
    "ip, private",
    [
        ("10.1.2.3", True),
        ("192.168.0.1", True),
        ("172.16.0.1", True),
        ("172.31.255.254", True),
        ("172.15.0.1", False),
        ("172.32.0.1", False),
        ("192.0.2.1", False),
        ("198.51.100.1", False),
        ("203.0.113.1", False),
    ],
)
def test_rfc1918_boundaries(parser, ip, private):
    assert parser._is_rfc1918(ip) is private


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "not a flow line",
        "2026-11-20T10:00:00,192.0.2.10,198.51.100.20,50000,443,TCP,512",  # missing packets
        "2026-11-20T10:00:00,192.0.2.10,198.51.100.20,port,443,TCP,512,4",
        "2026-11-20T10:00:00 192.0.2.11 -> 203.0.113.5:22 TCP",  # missing source port
        "Nov 20 10:00:00 demo-fw-01 kernel: DENY SRC=203.0.113.50 DST=192.0.2.10",  # no DPT
        "Nov 20 10:00:00 demo-host-01 sudo: alice.demo : COMMAND=/usr/bin/id",
        "SRC=" * 20_000,
        "x" * 100_000,
    ],
)
def test_malformed_lines_never_raise(parser, line):
    assert parser.can_parse(line) is False
    assert parser.parse(line, "dev-01") is None
