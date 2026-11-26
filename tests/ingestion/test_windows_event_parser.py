"""Fixture unit tests for WindowsEventParser (lsadra/ingestion/windows_event_parser.py)."""

import pytest

from lsadra.ingestion.windows_event_parser import _EVENT_MAP, WindowsEventParser

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _xml(event_id: str, data: dict, ns: bool = True) -> str:
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    xmlns = f' xmlns="{_NS}"' if ns else ""
    return (
        f"<Event{xmlns}><System><EventID>{event_id}</EventID>"
        '<TimeCreated SystemTime="2026-11-20T10:00:00.000Z"/>'
        "<Computer>DEMO-HOST-01</Computer></System>"
        f"<EventData>{fields}</EventData></Event>"
    )


@pytest.fixture
def parser():
    return WindowsEventParser()


@pytest.mark.parametrize("event_id", sorted(_EVENT_MAP))
def test_every_event_id_pipe_format(parser, event_id):
    line = f"{event_id}|2026-11-20T10:00:00Z|alice.demo|192.0.2.10|DEMO-HOST-01|"
    assert parser.can_parse(line) is True
    event = parser.parse(line, "dev-01")
    assert event is not None
    assert parser.validate_output(event)
    event_type, success = _EVENT_MAP[event_id]
    assert event["event_type"] == event_type
    assert event["success"] is success
    assert event["extra"]["event_id"] == event_id
    assert event["username"] == "alice.demo"
    assert event["source_ip"] == "192.0.2.10"
    assert event["timestamp"] == "2026-11-20T10:00:00+00:00"
    assert event["source_type"] == "windows_event"


@pytest.mark.parametrize("event_id", sorted(_EVENT_MAP))
def test_every_event_id_xml_format(parser, event_id):
    line = _xml(event_id, {"TargetUserName": "bob.demo", "IpAddress": "198.51.100.7"})
    assert parser.can_parse(line) is True
    event = parser.parse(line, "dev-01")
    assert event is not None
    assert parser.validate_output(event)
    assert event["event_type"] == _EVENT_MAP[event_id][0]
    assert event["success"] is _EVENT_MAP[event_id][1]
    assert event["extra"]["event_id"] == event_id
    assert event["extra"]["computer"] == "DEMO-HOST-01"
    assert event["username"] == "bob.demo"
    assert event["source_ip"] == "198.51.100.7"
    assert event["timestamp"] == "2026-11-20T10:00:00+00:00"


def test_xml_without_namespace(parser):
    event = parser.parse(_xml("4625", {"TargetUserName": "carol.demo"}, ns=False), "dev-01")
    assert event is not None
    assert event["event_type"] == "auth_failure"
    assert event["success"] is False
    assert event["username"] == "carol.demo"


def test_xml_detail_fields(parser):
    logon = parser.parse(
        _xml(
            "4624",
            {
                "TargetUserName": "dave.demo",
                "TargetDomainName": "DEMO",
                "LogonType": "10",
                "IpAddress": "203.0.113.9",
            },
        ),
        "dev-01",
    )
    assert logon["extra"]["logon_type"] == "RemoteInteractive"
    assert logon["extra"]["domain"] == "DEMO"

    process = parser.parse(
        _xml("4688", {"SubjectUserName": "erin.demo", "NewProcessName": "C:\\Demo\\tool.exe"}),
        "dev-01",
    )
    assert process["username"] == "erin.demo"  # falls back to SubjectUserName
    assert process["extra"]["process_name"] == "C:\\Demo\\tool.exe"

    task = parser.parse(_xml("4698", {"TaskName": "\\DemoTask"}), "dev-01")
    assert task["extra"]["task_name"] == "\\DemoTask"

    service = parser.parse(_xml("7045", {"ServiceName": "DemoSvc"}), "dev-01")
    assert service["extra"]["service_name"] == "DemoSvc"


@pytest.mark.parametrize("ip", ["-", "::1", "127.0.0.1", ""])
def test_local_or_empty_source_ip_is_dropped(parser, ip):
    event = parser.parse(f"4624|2026-11-20T10:00:00Z|alice.demo|{ip}|DEMO-HOST-01|", "dev-01")
    assert event["source_ip"] is None


def test_unknown_event_id_is_ignored(parser):
    pipe = "4999|2026-11-20T10:00:00Z|alice.demo|192.0.2.10|DEMO-HOST-01|"
    assert parser.can_parse(pipe) is False
    assert parser.parse(pipe, "dev-01") is None
    assert parser.parse(_xml("4999", {"TargetUserName": "alice.demo"}), "dev-01") is None


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "<Event><System><EventID>4624</EventID>",  # truncated XML
        "<Event xmlns='x'><System></System></Event>",  # no EventID
        "not a windows event",
        "Nov 20 10:00:00 demo-host-01 sudo: alice.demo : COMMAND=/usr/bin/id",
        "2026-11-20T10:00:00,192.0.2.10,198.51.100.20,50000,443,TCP,512,4",
        "4624|" + "x" * 100_000,
        "<Event>" + "<a>" * 5_000,
    ],
)
def test_malformed_lines_never_raise(parser, line):
    parser.can_parse(line)
    event = parser.parse(line, "dev-01")
    assert event is None or parser.validate_output(event)


def test_malformed_xml_returns_none(parser):
    assert parser.parse("<Event><System><EventID>4624</EventID>", "dev-01") is None
    assert parser.parse("", "dev-01") is None
    assert parser.parse("not a windows event", "dev-01") is None
