"""Fixture unit tests for EndpointParser (lsadra/ingestion/endpoint_parser.py)."""

import json

from lsadra.ingestion.endpoint_parser import EndpointParser


def test_parse_valid_pipe_delimited_and_json_lines():
    parser = EndpointParser()
    assert parser.source_type == "endpoint"

    pipe_line = (
        "2026-11-20T10:15:00Z|demo-host-01|alice.demo|notepad.exe|"
        "explorer.exe|notepad.exe notes.txt||process_create"
    )
    assert parser.can_parse(pipe_line) is True
    pipe_event = parser.parse(pipe_line, "fallback-host")
    assert pipe_event is not None
    assert pipe_event["source_type"] == "endpoint"
    assert pipe_event["device_id"] == "demo-host-01"
    assert pipe_event["username"] == "alice.demo"
    assert pipe_event["event_type"] == "process_create"
    assert pipe_event["timestamp"] == "2026-11-20T10:15:00"
    assert pipe_event["extra"]["process_name"] == "notepad.exe"
    assert pipe_event["extra"]["parent_process"] == "explorer.exe"
    assert pipe_event["extra"]["suspicious_cmdline"] is False
    assert pipe_event["extra"]["known_lolbin"] is False
    assert pipe_event["extra"]["unusual_parent"] is False

    json_line = json.dumps(
        {
            "timestamp": "2026-11-20T10:20:00Z",
            "device_id": "demo-host-02",
            "username": "bob.demo",
            "process_name": "python3",
            "parent_process": "bash",
            "cmdline": "python3 app.py",
            "file_path": "/srv/app.py",
            "action": "file_write",
        }
    )
    assert parser.can_parse(json_line) is True
    json_event = parser.parse(json_line, "fallback-host")
    assert json_event is not None
    assert json_event["device_id"] == "demo-host-02"
    assert json_event["username"] == "bob.demo"
    assert json_event["event_type"] == "file_write"
    assert json_event["extra"]["suspicious_cmdline"] is False
    assert json_event["extra"]["known_lolbin"] is False
    assert json_event["extra"]["unusual_parent"] is False


def test_enrichments_lolbin_suspicious_cmdline_and_unusual_parent():
    parser = EndpointParser()

    lolbin_line = (
        "2026-11-20T11:00:00Z|demo-host-03|carol.demo|certutil.exe|"
        "cmd.exe|certutil.exe -hashfile sample.txt||process_create"
    )
    lolbin_ev = parser.parse(lolbin_line, "demo-host-03")
    assert lolbin_ev is not None
    assert lolbin_ev["extra"]["known_lolbin"] is True

    encoded_ps_line = (
        "2026-11-20T11:05:00Z|demo-host-03|carol.demo|powershell.exe|"
        "explorer.exe|powershell.exe -enc SGVsbG8=||process_create"
    )
    ps_ev = parser.parse(encoded_ps_line, "demo-host-03")
    assert ps_ev is not None
    assert ps_ev["extra"]["suspicious_cmdline"] is True

    tmp_exec_line = (
        "2026-11-20T11:06:00Z|demo-host-03|carol.demo|bash|sshd|/tmp/check.sh||process_create"
    )
    tmp_ev = parser.parse(tmp_exec_line, "demo-host-03")
    assert tmp_ev is not None
    assert tmp_ev["extra"]["suspicious_cmdline"] is True

    parent_line = (
        "2026-11-20T11:10:00Z|demo-host-03|carol.demo|cmd.exe|"
        "winword.exe|cmd.exe /c echo ok||process_create"
    )
    parent_ev = parser.parse(parent_line, "demo-host-03")
    assert parent_ev is not None
    assert parent_ev["extra"]["unusual_parent"] is True


def test_invalid_and_empty_inputs_do_not_raise():
    parser = EndpointParser()

    assert parser.can_parse("") is False
    assert parser.parse("", "demo-host-01") is None
    assert parser.parse("   ", "demo-host-01") is None

    assert parser.can_parse("{not valid json") is False
    assert parser.parse("{not valid json", "demo-host-01") is None

    too_few_fields = "2026-11-20T12:00:00Z|demo-host-01|alice.demo"
    assert parser.can_parse(too_few_fields) is False
    assert parser.parse(too_few_fields, "demo-host-01") is None

    unknown_action_line = (
        "2026-11-20T12:05:00Z|demo-host-01|alice.demo|notepad.exe|"
        "explorer.exe|notepad.exe||unknown_action"
    )
    assert parser.can_parse(unknown_action_line) is False
    fallback_ev = parser.parse(unknown_action_line, "demo-host-01")
    assert fallback_ev is not None
    assert fallback_ev["event_type"] == "process_create"
