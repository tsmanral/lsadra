"""
Contract test — every demo corpus event must satisfy `event-schema.v1.json`.

The demo corpus is the only committed event data in the repo. It doubles as the
fixture for the M1 benchmark harness, so if it drifts away from the collector/
core contract, the benchmark silently measures the wrong thing. This test is the
tripwire.

It also enforces the synthetic-data hygiene rules that let this data live in a
public security repo: demo hostnames, `*.demo` users, and documentation-range
IPs only (RFC5737 / RFC3849).
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest

jsonschema = pytest.importorskip("jsonschema", reason="jsonschema is required for contract tests")

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "demo" / "corpus"
SCHEMA_PATH = REPO_ROOT / "docs" / "contracts" / "event-schema.v1.json"

EXPECTED_SCENARIOS = {
    "ssh_bruteforce",
    "persistence_new_service",
    "data_movement_offhours",
    "benign_background",
}

VALID_LABELS = {"malicious", "benign", "suspicious"}

# RFC5737 TEST-NET-1/2/3 and RFC3849 documentation prefix.
DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]


def _corpus_files() -> List[Path]:
    return sorted(CORPUS_DIR.glob("*.jsonl"))


def _iter_events() -> Iterator[Tuple[Path, int, Dict[str, Any]]]:
    """Yield (file, line number, event) for every corpus line."""
    for path in _corpus_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            yield path, lineno, json.loads(line)


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def test_expected_scenario_files_exist():
    assert {p.stem for p in _corpus_files()} == EXPECTED_SCENARIOS


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda p: p.stem)
def test_file_is_valid_jsonl(path: Path):
    """Every non-empty line parses as a JSON object; the file is non-trivial."""
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n"), f"{path.name} must end with a newline"

    count = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        assert line.strip(), f"{path.name}:{lineno}: blank line not allowed in JSONL"
        obj = json.loads(line)
        assert isinstance(obj, dict), f"{path.name}:{lineno}: each line must be an object"
        count += 1
    assert count >= 20, f"{path.name}: expected a meaningful scenario, got {count} events"


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda p: p.stem)
def test_events_validate_against_schema(path: Path, validator):
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        errors = sorted(validator.iter_errors(json.loads(line)), key=lambda e: e.path)
        assert not errors, (
            f"{path.name}:{lineno}: schema violation — "
            + "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
        )


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda p: p.stem)
def test_every_event_carries_ground_truth(path: Path):
    """Labels are what make the corpus usable for evaluation, so they are required."""
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        event = json.loads(line)
        truth = event.get("attributes", {}).get("ground_truth")
        assert isinstance(truth, dict), f"{path.name}:{lineno}: missing attributes.ground_truth"
        assert truth.get("label") in VALID_LABELS, (
            f"{path.name}:{lineno}: label {truth.get('label')!r} not in {sorted(VALID_LABELS)}"
        )
        assert truth.get("scenario") == path.stem, (
            f"{path.name}:{lineno}: scenario {truth.get('scenario')!r} != file stem {path.stem!r}"
        )
        assert "phase" in truth, f"{path.name}:{lineno}: ground_truth.phase is required"


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda p: p.stem)
def test_timestamps_are_ordered(path: Path):
    stamps = [
        json.loads(line)["timestamp"]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert stamps == sorted(stamps), f"{path.name}: timestamps must ascend within a scenario"


def test_data_is_obviously_synthetic():
    """
    Public-repo hygiene: hosts, users and IPs must be unmistakably fake.

    This is the guard that keeps a real log line from ever being pasted into the
    corpus during a future edit.
    """
    for path, lineno, event in _iter_events():
        where = f"{path.name}:{lineno}"

        host = event.get("host", "")
        assert host.startswith("demo-host-"), f"{where}: host {host!r} must be demo-host-NN"

        user = event.get("effective_username", "")
        if user:
            assert user.endswith(".demo"), f"{where}: username {user!r} must end with .demo"

        source_ip = event.get("source_ip")
        if source_ip:
            addr = ipaddress.ip_address(source_ip)
            assert any(addr in net for net in DOC_NETWORKS), (
                f"{where}: {source_ip} is outside the RFC5737/RFC3849 documentation ranges"
            )


def test_benign_control_set_is_entirely_benign():
    """The negative class must stay clean or false-positive measurement is meaningless."""
    path = CORPUS_DIR / "benign_background.jsonl"
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        truth = json.loads(line)["attributes"]["ground_truth"]
        assert truth["label"] == "benign", f"{path.name}:{lineno}: control set must be all-benign"


def test_attack_scenarios_contain_malicious_events():
    for stem in EXPECTED_SCENARIOS - {"benign_background"}:
        path = CORPUS_DIR / f"{stem}.jsonl"
        labels = {
            json.loads(line)["attributes"]["ground_truth"]["label"]
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        assert "malicious" in labels, f"{path.name}: attack scenario has no malicious events"


def test_seeder_payload_mapping_drops_contract_only_fields():
    """`schema_version` is a contract field; the ingestion API rejects unknown keys."""
    import sys

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from seed_demo import to_ingest_payload  # noqa: E402

    _, _, event = next(_iter_events())
    payload = to_ingest_payload(event)

    assert "schema_version" not in payload
    assert set(payload) == {
        "timestamp",
        "host",
        "effective_username",
        "source_ip",
        "event_type",
        "raw_message",
        "attributes",
    }
    assert payload["attributes"]["ground_truth"]["label"] in VALID_LABELS


def test_time_shift_preserves_spacing_and_lands_on_anchor():
    import sys
    from datetime import datetime, timezone

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from seed_demo import _parse_ts, time_shift  # noqa: E402

    events = [e for _, _, e in _iter_events()]
    events.sort(key=lambda e: e["timestamp"])
    anchor = datetime(2030, 1, 1, tzinfo=timezone.utc)

    shifted = time_shift(events, anchor=anchor)

    assert max(_parse_ts(e["timestamp"]) for e in shifted) == anchor
    original_span = _parse_ts(events[-1]["timestamp"]) - _parse_ts(events[0]["timestamp"])
    shifted_span = _parse_ts(shifted[-1]["timestamp"]) - _parse_ts(shifted[0]["timestamp"])
    assert original_span == shifted_span
