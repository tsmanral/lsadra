"""
Event contract v1 — enforcement at the ingestion boundary.

`docs/contracts/event-schema.v1.json` is the source of truth. These tests pin
three things so the contract cannot silently drift:

1. **Compatibility** — `NormalizedEvent.model_json_schema()` is equal, keyword
   for keyword, to the frozen schema (annotations aside). Changing a bound on
   either side alone fails here.
2. **Differential behaviour** — for every rule, a mutated event is rejected by
   the JSON Schema validator *and* by the pydantic model, except where the
   contract says the rule is core-enforced (`readOnly`, `x-lsadra-*`).
3. **Boundary** — the corpus ingests (200) through the real HTTP route, and
   each mutated event is a 422 naming the offending field (never a 5xx).

SYNTHETIC data only: documentation-range IPs, `demo-host-NN`, `*.demo` users.
"""

from __future__ import annotations

import ast
import copy
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

jsonschema = pytest.importorskip("jsonschema", reason="jsonschema is required for contract tests")

from lsadra.ingestion.api_ingestion import (  # noqa: E402
    RFC3339_PATTERN,
    NormalizedEvent,
)
from tests.fixtures import setup_test_db  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "docs" / "contracts" / "event-schema.v1.json"
CORPUS_DIR = REPO_ROOT / "demo" / "corpus"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())

# Keywords that describe rather than constrain; ignored by the compatibility check.
ANNOTATIONS = {"title", "description", "default", "examples", "$comment"}

BASE_EVENT: Dict[str, Any] = {
    "schema_version": "1",
    "timestamp": "2026-01-15T02:01:12Z",
    "host": "demo-host-01",
    "effective_username": "alice.demo",
    "source_ip": "192.0.2.45",
    "event_type": "auth_failure",
    "raw_message": "demo: Failed password for alice.demo from 192.0.2.45 port 51422 ssh2",
    "attributes": {"service": "sshd", "pid": 18402},
}


# ── helpers ────────────────────────────────────────────────────────────────


def _strip(node: Any) -> Any:
    """Drop annotation keywords recursively; canonicalise anyOf order."""
    if isinstance(node, dict):
        out = {k: _strip(v) for k, v in node.items() if k not in ANNOTATIONS}
        if "anyOf" in out:
            out["anyOf"] = sorted(out["anyOf"], key=lambda s: json.dumps(s, sort_keys=True))
        return out
    if isinstance(node, list):
        return [_strip(v) for v in node]
    return node


def _schema_accepts(event: Any) -> bool:
    return VALIDATOR.is_valid(event)


def _model_accepts(event: Any) -> bool:
    try:
        NormalizedEvent.model_validate(event)
    except Exception:  # pydantic.ValidationError; anything else would also be a rejection
        return False
    return True


def _corpus_events() -> List[Tuple[str, List[Dict[str, Any]]]]:
    out = []
    for path in sorted(CORPUS_DIR.glob("*.jsonl")):
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        out.append((path.stem, events))
    return out


def _attrs_of_exact_size(total_bytes: int) -> Dict[str, str]:
    """Attributes whose compact-JSON UTF-8 size is exactly *total_bytes*, each value ≤ 1024."""
    attrs: Dict[str, str] = {}
    i = 0
    while True:
        attrs[f"k{i:02d}"] = ""
        size = len(json.dumps(attrs, separators=(",", ":")).encode("utf-8"))
        room = total_bytes - size
        if room <= 1024:
            attrs[f"k{i:02d}"] = "x" * room
            return attrs
        attrs[f"k{i:02d}"] = "x" * 1024
        i += 1


def _with(**changes: Any) -> Callable[[Dict[str, Any]], None]:
    def mutate(event: Dict[str, Any]) -> None:
        event.update(changes)
    return mutate


def _without(field: str) -> Callable[[Dict[str, Any]], None]:
    def mutate(event: Dict[str, Any]) -> None:
        event.pop(field)
    return mutate


# (case id, field the error must name, mutation, JSON Schema also rejects?)
# `False` in the last column marks rules the contract declares core-enforced:
# readOnly fields (JSON Schema lets an authority reject them) and x-lsadra-*.
MUTATIONS: List[Tuple[str, str, Callable[[Dict[str, Any]], None], bool]] = [
    ("schema_version-missing", "schema_version", _without("schema_version"), True),
    ("schema_version-2", "schema_version", _with(schema_version="2"), True),
    ("schema_version-int", "schema_version", _with(schema_version=1), True),
    ("timestamp-missing", "timestamp", _without("timestamp"), True),
    ("timestamp-naive", "timestamp", _with(timestamp="2026-01-15T02:01:12"), True),
    ("timestamp-epoch", "timestamp", _with(timestamp=1768442472), True),
    ("timestamp-space-sep", "timestamp", _with(timestamp="2026-01-15 02:01:12Z"), True),
    ("timestamp-date-only", "timestamp", _with(timestamp="2026-01-15"), True),
    ("timestamp-leap-second", "timestamp", _with(timestamp="2026-12-31T23:59:60Z"), True),
    ("device_id-client-supplied", "device_id", _with(device_id="spoofed-device"), False),
    ("user_id-client-supplied", "user_id", _with(user_id="spoofed-user"), False),
    ("unknown-field", "severity", _with(severity="HIGH"), True),
    ("host-too-long", "host", _with(host="h" * 256), True),
    ("host-null", "host", _with(host=None), True),
    ("effective_username-too-long", "effective_username", _with(effective_username="u" * 129), True),
    ("source_ip-hostname", "source_ip", _with(source_ip="attacker.demo"), True),
    ("source_ip-empty", "source_ip", _with(source_ip=""), True),
    ("source_ip-ipv6-zone", "source_ip", _with(source_ip="fe80::1%eth0"), True),
    ("source_ip-too-long", "source_ip", _with(source_ip="2001:db8::" + "1" * 40), True),
    ("event_type-missing", "event_type", _without("event_type"), True),
    ("event_type-too-long", "event_type", _with(event_type="e" * 65), True),
    ("raw_message-too-long", "raw_message", _with(raw_message="r" * 4097), True),
    ("attributes-not-object", "attributes", _with(attributes=["a", "b"]), True),
    ("attributes-33-keys", "attributes", _with(attributes={f"k{i}": i for i in range(33)}), True),
    ("attributes-string-value-1025", "attributes", _with(attributes={"cmd": "c" * 1025}), True),
    ("attributes-nested-value-over-1024", "attributes", _with(attributes={"ports": list(range(300))}), False),
    ("attributes-total-8193-bytes", "attributes", _with(attributes=_attrs_of_exact_size(8193)), False),
]

# Boundary inputs that MUST be accepted by both sides (guards off-by-one tightening).
ACCEPTED: List[Tuple[str, Callable[[Dict[str, Any]], None]]] = [
    ("offset-+05:30", _with(timestamp="2026-01-15T07:31:12+05:30")),
    ("lowercase-t-z", _with(timestamp="2026-01-15t02:01:12z")),
    ("fractional-seconds-9", _with(timestamp="2026-01-15T02:01:12.123456789Z")),
    ("source_ip-null", _with(source_ip=None)),
    ("source_ip-ipv6", _with(source_ip="2001:db8::45")),
    ("source_ip-ipv4-mapped-ipv6", _with(source_ip="::ffff:192.0.2.45")),
    ("only-required-fields", lambda e: [e.pop(k) for k in list(e) if k not in {"schema_version", "timestamp", "event_type"}]),
    ("host-255", _with(host="h" * 255)),
    ("effective_username-128", _with(effective_username="u" * 128)),
    ("event_type-64", _with(event_type="e" * 64)),
    ("raw_message-4096", _with(raw_message="r" * 4096)),
    ("attributes-32-keys", _with(attributes={f"k{i}": i for i in range(32)})),
    ("attributes-string-value-1024", _with(attributes={"cmd": "c" * 1024})),
    ("attributes-total-8192-bytes", _with(attributes=_attrs_of_exact_size(8192))),
]


def _mutated(mutate: Callable[[Dict[str, Any]], None]) -> Dict[str, Any]:
    event = copy.deepcopy(BASE_EVENT)
    mutate(event)
    return event


# ── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    setup_test_db(tmp_path)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from server import app

    return TestClient(app)


@pytest.fixture
def device_headers():
    """A registered device (fresh ID per test: the rate limiter is process-global)."""
    from lsadra.storage.database import create_device, create_user

    user_id, device_id = f"u-{uuid.uuid4().hex[:8]}", f"demo-dev-{uuid.uuid4().hex[:8]}"
    create_user(user_id, f"{user_id}.demo", "hash", "ANALYST")
    create_device(device_id, user_id, "demo-host-01", "linux", "demo-key-not-a-secret")
    return {"X-Device-Id": device_id, "X-API-Key": "demo-key-not-a-secret"}


@pytest.fixture
def no_detection():
    """Detection is not under test here; keep the boundary tests fast and focused."""
    with patch("lsadra.ingestion.api_ingestion._get_orchestrator", return_value=MagicMock()):
        yield


def _error_locs(response) -> List[List[Any]]:
    return [err["loc"] for err in response.json()["detail"]]


# ── 1. the contract file itself ────────────────────────────────────────────


def test_schema_is_frozen_v1():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert "draft" not in SCHEMA["description"].lower()
    assert "example.invalid" not in SCHEMA["$id"]
    assert SCHEMA["$id"].endswith("/docs/contracts/event-schema.v1.json")
    assert SCHEMA["properties"]["schema_version"]["const"] == "1"
    assert SCHEMA["additionalProperties"] is False


def test_timestamp_pattern_is_shared():
    assert SCHEMA["properties"]["timestamp"]["pattern"] == RFC3339_PATTERN


# ── 2. model ↔ schema compatibility ───────────────────────────────────────


def test_model_json_schema_matches_contract():
    model = NormalizedEvent.model_json_schema()
    read_only = {k for k, v in SCHEMA["properties"].items() if v.get("readOnly")}

    assert read_only == {"device_id", "user_id"}
    assert model["additionalProperties"] is False
    assert set(model["required"]) == set(SCHEMA["required"])
    assert set(model["properties"]) == set(SCHEMA["properties"]) - read_only
    for name, prop in model["properties"].items():
        assert _strip(prop) == _strip(SCHEMA["properties"][name]), f"drift in {name!r}"


# ── 3. differential behaviour: schema and model agree ──────────────────────


@pytest.mark.parametrize("case_id,field,mutate,schema_rejects", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutation_rejected_by_model_and_schema(case_id, field, mutate, schema_rejects):
    event = _mutated(mutate)
    assert not _model_accepts(event), f"{case_id}: model accepted a contract violation"
    assert _schema_accepts(event) is (not schema_rejects), (
        f"{case_id}: JSON Schema verdict disagrees with the declared rule"
    )


@pytest.mark.parametrize("case_id,mutate", ACCEPTED, ids=[a[0] for a in ACCEPTED])
def test_boundary_accepted_by_model_and_schema(case_id, mutate):
    event = _mutated(mutate)
    assert _schema_accepts(event), f"{case_id}: schema rejected {list(VALIDATOR.iter_errors(event))}"
    assert _model_accepts(event), f"{case_id}: model rejected a valid event"


def test_corpus_validates_against_schema_and_model():
    for stem, events in _corpus_events():
        for i, event in enumerate(events, 1):
            assert _schema_accepts(event), f"{stem}:{i}"
            assert _model_accepts(event), f"{stem}:{i}"


# ── 4. the HTTP boundary ───────────────────────────────────────────────────


def test_corpus_ingests_through_http(client, device_headers, no_detection):
    from lsadra.storage.database import get_events_since

    total = 0
    for stem, events in _corpus_events():
        assert len(events) <= 100, f"{stem}: split into batches of 100"
        r = client.post("/api/events/batch", json={"events": events}, headers=device_headers)
        assert r.status_code == 200, f"{stem}: {r.text[:500]}"
        assert r.json()["events_accepted"] == len(events)
        total += len(events)

    rows = get_events_since(device_headers["X-Device-Id"], after_id=0)
    assert len(rows) == total
    # Server-assigned identity, UTC-normalized timestamps.
    assert {row["device_id"] for row in rows} == {device_headers["X-Device-Id"]}
    assert all(row["timestamp"].endswith("+00:00") for row in rows)


@pytest.mark.parametrize("case_id,field,mutate,schema_rejects", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutated_event_is_422_naming_field(client, device_headers, no_detection, case_id, field, mutate, schema_rejects):
    event = _mutated(mutate)
    with patch("lsadra.ingestion.api_ingestion.insert_events_batch") as insert:
        r = client.post("/api/events/batch", json={"events": [BASE_EVENT, event]}, headers=device_headers)
    locs = _error_locs(r) if r.status_code == 422 else []
    print(f"{case_id}: HTTP {r.status_code} loc={locs[:1]}")
    assert r.status_code == 422, r.text[:500]
    assert any(loc[:3] == ["body", "events", 1] and field in loc for loc in locs), locs
    insert.assert_not_called()  # the whole batch is rejected, nothing written


def test_utc_normalization_and_offsets(client, device_headers, no_detection):
    from lsadra.storage.database import get_events_since

    event = _mutated(_with(timestamp="2026-01-15T07:31:12.5+05:30"))
    r = client.post("/api/events/batch", json={"events": [event]}, headers=device_headers)
    assert r.status_code == 200, r.text
    (row,) = get_events_since(device_headers["X-Device-Id"], after_id=0)
    assert row["timestamp"] == "2026-01-15T02:01:12.500000+00:00"


@pytest.mark.parametrize(
    "body,expected_loc",
    [
        ({"events": [BASE_EVENT] * 101}, ["body", "events"]),
        ({"events": [BASE_EVENT], "device_id": "x"}, ["body", "device_id"]),
        ({"events": [BASE_EVENT], "sent_at": "2026-01-15T02:01:12Z"}, ["body", "sent_at"]),
        ({}, ["body", "events"]),
        ({"events": "nope"}, ["body", "events"]),
    ],
    ids=["101-events", "envelope-device_id", "envelope-sent_at", "no-events", "events-not-list"],
)
def test_batch_envelope_is_422(client, device_headers, body, expected_loc):
    r = client.post("/api/events/batch", json=body, headers=device_headers)
    assert r.status_code == 422, r.text[:300]
    assert expected_loc in _error_locs(r)


@pytest.mark.parametrize(
    "raw_body",
    [
        b"{not json",
        b"[]",
        b"null",
        b'{"events": [' * 5000,  # pathologically deep nesting
        ('{"events": [{"schema_version": "1", "timestamp": "2026-01-15T02:01:12Z", '
         '"event_type": "x", "attributes": {"n": ' + "9" * 5000 + "}}]}").encode(),  # int > str-conversion limit
        ('{"events": [{"schema_version": "1", "timestamp": "2026-01-15T02:01:12Z", '
         '"event_type": "x", "attributes": {"n": ' + "[" * 3000 + "]" * 3000 + "}}]}").encode(),  # deep attribute value
        ('{"events": ' + "[" * 3000 + "]" * 3000 + "}").encode(),  # deep, well-formed, wrong type
        b'{"events": [{"schema_version": "1", "timestamp": "9999-12-31T23:59:59-23:59", "event_type": "x"}]}',
        b'{"events": [{"schema_version": "1", "timestamp": "2026-01-15T02:01:12Z", "event_type": "x", '
        b'"host": "demo\\ud800"}]}',  # lone surrogate
    ],
    ids=["invalid-json", "top-level-array", "null", "deep-nesting", "huge-int", "deep-attribute",
         "deep-events", "utc-overflow", "lone-surrogate"],
)
def test_malformed_body_is_4xx_never_5xx(client, device_headers, no_detection, raw_body):
    headers = {**device_headers, "Content-Type": "application/json"}
    r = client.post("/api/events/batch", content=raw_body, headers=headers)
    assert 400 <= r.status_code < 500, (r.status_code, r.text[:300])


# ── /api/events/raw ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "line,expected_loc",
    [
        ({"raw_line": "x", "source_hint": "windows_event"}, ["body", "lines", 0, "source_hint"]),
        ({"raw_line": "x", "source_hint": "SSH"}, ["body", "lines", 0, "source_hint"]),
        ({"raw_line": "r" * 4097}, ["body", "lines", 0, "raw_line"]),
        ({"raw_line": "x", "device_id": "spoofed"}, ["body", "lines", 0, "device_id"]),
    ],
    ids=["hint-not-in-enum", "hint-wrong-case", "raw_line-too-long", "unknown-key"],
)
def test_raw_line_contract_is_422(client, device_headers, line, expected_loc):
    r = client.post("/api/events/raw", json={"lines": [line]}, headers=device_headers)
    assert r.status_code == 422, r.text[:300]
    assert expected_loc in _error_locs(r)


@pytest.mark.parametrize("hint", ["ssh", "syslog", "windows", "network", "endpoint", None])
def test_raw_accepts_documented_hints(client, device_headers, no_detection, hint):
    line = {"raw_line": "Jan 15 02:01:12 demo-host-07 sshd[18402]: Failed password for alice.demo "
                        "from 192.0.2.45 port 51422 ssh2"}
    if hint is not None:
        line["source_hint"] = hint
    r = client.post("/api/events/raw", json={"lines": [line]}, headers=device_headers)
    assert r.status_code == 200, r.text[:300]


@pytest.mark.parametrize(
    "raw_line,hint",
    [
        ("Jan 15 02:01:12 demo-host-07 sshd[18402]: Failed password for alice.demo from 192.0.2.45 port 51422 ssh2", "ssh"),
        ("Jan 15 02:01:12 demo-host-07 sudo[999]: alice.demo : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/true", "syslog"),
    ],
    ids=["ssh", "syslog"],
)
def test_raw_host_is_log_hostname_not_device_id(client, device_headers, no_detection, raw_line, hint):
    from lsadra.storage.database import get_events_since

    r = client.post("/api/events/raw", json={"lines": [{"raw_line": raw_line, "source_hint": hint}]},
                    headers=device_headers)
    assert r.status_code == 200 and r.json()["accepted"] == 1, r.text[:300]
    (row,) = get_events_since(device_headers["X-Device-Id"], after_id=0)
    assert row["device_id"] == device_headers["X-Device-Id"]
    assert row["host"] == "demo-host-07"


# ── producers ──────────────────────────────────────────────────────────────


def _load_function(path: Path, name: str, namespace: Dict[str, Any]) -> Callable[..., Any]:
    """Exec one top-level function from a script that cannot be imported (it runs on import)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    (fn,) = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
    exec(compile(ast.Module(body=[fn], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[name]


def _producer_events() -> List[Tuple[str, Dict[str, Any]]]:
    import sys

    from lsadra.endpoint_agent.linux_agent import _parse_line

    events: List[Tuple[str, Dict[str, Any]]] = []
    for line in [
        "Jan 15 02:01:12 demo-host-01 sshd[18402]: Failed password for alice.demo from 192.0.2.45 port 51422 ssh2",
        "Jan 15 02:01:12 demo-host-01 sshd[18402]: Accepted publickey for alice.demo from 2001:db8::45 port 51422 ssh2",
        "Jan 15 02:01:12 demo-host-01 sshd[18402]: Failed password for alice.demo from gw.demo port 51422 ssh2",
        "2026-01-15T02:01:12.123+01:00 demo-host-01 sshd[18402]: Failed password for alice.demo from 192.0.2.45 port 1 ssh2",
        "2026-01-15T02:01:12 demo-host-01 sshd[18402]: Failed password for alice.demo from 192.0.2.45 port 1 ssh2",
        "Jan 15 02:01:12 demo-host-01 sudo[999]: alice.demo : TTY=pts/0 ; COMMAND=/bin/" + "x" * 5000,
    ]:
        ev = _parse_line(line)
        assert ev is not None, line
        events.append((f"linux_agent:{line[:40]}", ev))

    make_event = _load_function(
        REPO_ROOT / "fleet_simulator.py",
        "make_event",
        {"datetime": datetime, "timezone": timezone, "timedelta": timedelta, "random": random,
         "NORMAL_USERS": ["alice.demo"]},
    )
    device = {"hostname": "demo-host-02"}
    events.append(("fleet_simulator:default", make_event(device)))
    events.append(("fleet_simulator:attack", make_event(device, "auth_failure", "alice.demo", "198.51.100.7",
                                                       datetime(2026, 1, 15, tzinfo=timezone.utc))))

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from seed_demo import time_shift, to_ingest_payload  # noqa: E402

    _, corpus = _corpus_events()[0]
    for ev in time_shift(corpus[:3]):
        events.append(("seed_demo", to_ingest_payload(ev)))
    return events


def test_producer_events_satisfy_contract():
    events = _producer_events()
    assert len(events) >= 10
    for name, event in events:
        assert event.get("schema_version") == "1", name
        assert _schema_accepts(event), f"{name}: {[e.message for e in VALIDATOR.iter_errors(event)]}"
        assert _model_accepts(event), name


def test_linux_agent_sends_a_valid_batch_and_drops_on_422():
    """The agent's wire payload is a valid EventBatch; a 422 is dropped, not retried forever."""
    import io
    import urllib.error

    from lsadra.endpoint_agent import linux_agent
    from lsadra.ingestion.api_ingestion import EventBatch

    events = [e for name, e in _producer_events() if name.startswith("linux_agent")]
    sent: List[bytes] = []

    class _Ok:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _capture(req, timeout):
        sent.append(req.data)
        return _Ok()

    with patch.object(linux_agent.urllib.request, "urlopen", side_effect=_capture):
        assert linux_agent._send_batch(events, "http://core.demo", "/api/events/batch", "dev", "key")
    EventBatch.model_validate(json.loads(sent[0]))  # raises on any contract violation

    rejected = urllib.error.HTTPError("http://core.demo", 422, "Unprocessable", {}, io.BytesIO(b"{}"))
    with patch.object(linux_agent.urllib.request, "urlopen", side_effect=rejected) as urlopen, \
            patch.object(linux_agent.time, "sleep") as sleep:
        assert linux_agent._send_batch(events, "http://core.demo", "/api/events/batch", "dev", "key") is False
    assert urlopen.call_count == 1 and not sleep.called


def test_raw_producers_use_documented_hints():
    allowed = {"ssh", "syslog", "windows", "network", "endpoint"}
    tree = ast.parse((REPO_ROOT / "windows_live_agent.py").read_text(encoding="utf-8"))
    hints = [
        v.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        for k, v in zip(node.keys, node.values)
        if isinstance(k, ast.Constant) and k.value == "source_hint" and isinstance(v, ast.Constant)
    ]
    assert hints and set(hints) <= allowed, hints
