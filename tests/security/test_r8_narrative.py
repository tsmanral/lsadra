"""
R8 — narratives built from the injection corpus stay inert.

Attacker story: an attacker who gets one log line ingested controls the strings
the rule-based narrative engine interpolates (IP, user, host/device, event
type, source type, rule reason). Pre-R8 they reached stored, markdown-rendered
narratives verbatim. These tests drive every narrative entry point with every
event of `demo/corpus/injection_attempts.jsonl` and assert:

* no raw payload survives (a payload containing markup/controls never appears verbatim);
* no control/format characters appear except the template's own newlines;
* the markdown *structure* of the output — the sequence of unescaped markup
  characters and newlines — is identical to the same narrative built from
  benign placeholder values (so a payload cannot add, close or reorder markup);
* length caps hold, with a visible truncation marker.

A static check also pins the rule "every interpolation goes through clean_field"
so a future template edit cannot silently reintroduce a raw site.
"""

from __future__ import annotations

import ast
import json
import unicodedata
from pathlib import Path
from typing import Any, Dict, List

import pytest

from lsadra.explainability import narrative_builder as nb
from lsadra.explainability.sanitize import MARKDOWN_SPECIALS, MAX_TEXT, TRUNCATION_MARKER

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS = REPO_ROOT / "demo" / "corpus" / "injection_attempts.jsonl"
FAMILIES = {
    "delimiter-markdown-breakout",
    "instruction-override",
    "homoglyph-bidi-invisible",
    "oversize-fields",
    "nested-json-raw-message",
}
RULE_TYPES = [
    "BRUTE_FORCE",
    "CREDENTIAL_STUFFING",
    "LOW_AND_SLOW",
    "LATERAL_MOVEMENT",
    "PORT_SCAN",
    "LARGE_DATA_TRANSFER",
    "SUSPICIOUS_PROCESS",
    "PRIVILEGE_ESCALATION",
    "PERSISTENCE",
    "SOMETHING_UNMAPPED",  # _narrate_generic
]
ALERT_NARRATIVE_MAX = 1200
SUMMARY_MAX = 16000


def _load() -> List[Dict[str, Any]]:
    return [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]


EVENTS = _load()


# ── structural helpers ────────────────────────────────────────────────────


def skeleton(text: str) -> List[str]:
    """Unescaped markdown-special characters and newlines, in order."""
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] in MARKDOWN_SPECIALS:
            i += 2
            continue
        if ch in MARKDOWN_SPECIALS or ch == "\n":
            out.append(ch)
        i += 1
    return out


def shadow(value: Any, table: Dict[str, str]) -> Any:
    """Replace every string leaf with a unique benign token, keeping distinctness."""
    if isinstance(value, str):
        return table.setdefault(value, f"tok{len(table)}")
    if isinstance(value, dict):
        return {k: shadow(v, table) for k, v in value.items()}
    if isinstance(value, list):
        return [shadow(v, table) for v in value]
    return value


def hostile_strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for kv in value.items() for v in kv for s in hostile_strings(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in hostile_strings(v)]
    return []


def _needs_neutralising(s: str) -> bool:
    return any(c in MARKDOWN_SPECIALS or unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in s) or (
        unicodedata.normalize("NFKC", s) != s
    )


def assert_inert(out: str, inputs: Any, reference: str) -> None:
    bad = [hex(ord(c)) for c in out if c != "\n" and unicodedata.category(c) in {"Cc", "Cf", "Cs", "Cn"}]
    assert not bad, f"control/format characters survived: {bad}"
    for s in hostile_strings(inputs):
        if len(s) >= 3 and _needs_neutralising(s):
            assert s not in out, f"raw payload survived: {s[:80]!r}"
    assert skeleton(out) == skeleton(reference), "payload changed the markdown structure"


# ── input builders (corpus event → narrative inputs) ──────────────────────


def alert_inputs(event: Dict[str, Any], rule_type: str):
    features = {
        "source_ip": event["source_ip"],
        "effective_username": event["effective_username"],
        "username": event["effective_username"],
        "device_id": event["host"],
        "event_type": event["event_type"],
        "source_type": event["event_type"],
        "dest_ip": event["host"],
        "failed_logins_last_5min": 12,
        "failed_logins_last_15min": 40,
        "login_attempt_velocity": 2.4,
        "unique_usernames_per_ip": 7,
        "failure_ratio": 0.9,
        "cross_source_activity": True,
        "unique_ips_per_username": 3,
        "unique_dst_ports_per_ip": 90,
        "total_bytes_out": 5e8,
        "suspicious_process_count": 4,
        "lolbin_usage_count": 2,
    }
    rule_alert = {
        "type": rule_type,
        "reason": event["raw_message"],
        "mitre_id": event["event_type"],
        "ip": event["source_ip"],
        "affected_users": ",".join([event["effective_username"], event["host"], event["event_type"]]),
    }
    timeline = [
        {"timestamp": event["timestamp"] + event["event_type"]},
        {"timestamp": event["raw_message"]},
    ]
    shap_values = {event["event_type"]: 0.5, "failures_15m": 0.1}
    return features, rule_alert, shap_values, timeline


def timeline_of(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "timestamp": e["timestamp"],
            "event_type": e["event_type"],
            "device_id": e["host"],
            "effective_username": e["effective_username"],
            "source_type": e["attributes"]["ground_truth"]["phase"] + e["event_type"],
        }
        for e in events
    ]


def summary_inputs(events: List[Dict[str, Any]]):
    first = events[0]
    incident = {
        "attack_type": first["event_type"],
        "severity_label": first["effective_username"],
        "first_seen": first["raw_message"],
        "last_seen": events[-1]["host"],
        "anomaly_count": first["event_type"],
    }
    threat_intel = {"abuse_score": 90, "country_code": first["host"]}  # score is numeric in the TI cache
    past = [{"attack_type": e["event_type"]} for e in events]
    return first["host"], incident, timeline_of(events), past, threat_intel


def _ids(events):
    return [f"{i + 1:02d}-{e['attributes']['ground_truth']['phase']}" for i, e in enumerate(events)]


# ── tests ─────────────────────────────────────────────────────────────────


def test_corpus_covers_every_payload_family():
    assert {e["attributes"]["ground_truth"]["phase"] for e in EVENTS} == FAMILIES
    assert {e["attributes"]["ground_truth"]["label"] for e in EVENTS} == {"suspicious"}


@pytest.mark.parametrize("event", EVENTS, ids=_ids(EVENTS))
@pytest.mark.parametrize("rule_type", RULE_TYPES)
def test_alert_narrative_is_inert(event, rule_type):
    args = alert_inputs(event, rule_type)
    out = nb.generate_alert_narrative(*args[:3], entity_timeline=args[3])
    features, rule_alert, shap_values, timeline = shadow(list(args), {})
    shap_values = {f"tokshap{i}": v for i, v in enumerate(args[2].values())}  # keys are hostile too
    ref = nb.generate_alert_narrative(features, rule_alert, shap_values, entity_timeline=timeline)
    assert not out.startswith("Narrative unavailable"), out[:200]
    assert_inert(out, args, ref)
    assert len(out) <= ALERT_NARRATIVE_MAX


@pytest.mark.parametrize("event", EVENTS, ids=_ids(EVENTS))
def test_v3_builder_is_inert(event):
    kwargs = dict(
        threat_type=event["event_type"],
        mitre_id=event["effective_username"],
        row_data={
            "source_ip": event["raw_message"],
            "effective_username": event["effective_username"],
            "device_id": event["host"],
            "failures_15m": 30,
            "unique_users_15m": 4,
            "is_off_hours": 1,
        },
        layer1_z=5.0,
        layer2_score=0.8,
        layer3_error=0.1,
        severity_context={
            "severity_label": event["event_type"],
            "severity_score": 0.9,
            "urgency": event["raw_message"],
        },
    )
    out = nb.NarrativeBuilder.build(**kwargs)
    ref = nb.NarrativeBuilder.build(**shadow(kwargs, {}))
    assert_inert(out, kwargs, ref)
    assert len(out) <= ALERT_NARRATIVE_MAX


@pytest.mark.parametrize("event", EVENTS, ids=_ids(EVENTS))
def test_investigative_summary_is_inert_per_event(event):
    args = summary_inputs([event])
    out = nb.generate_investigative_summary(*args)
    ref = nb.generate_investigative_summary(*shadow(list(args), {}))
    assert not out.startswith("**Investigation report unavailable"), out[:200]
    assert_inert(out, args, ref)
    assert len(out) <= SUMMARY_MAX


def test_investigative_summary_over_whole_corpus():
    args = summary_inputs(EVENTS)
    out = nb.generate_investigative_summary(*args)
    ref = nb.generate_investigative_summary(*shadow(list(args), {}))
    assert_inert(out, args, ref)
    assert len(out) <= SUMMARY_MAX
    assert TRUNCATION_MARKER in out


def test_timeline_text_over_whole_corpus():
    tl = timeline_of(EVENTS)
    out = nb.format_timeline_text(tl)
    assert_inert(out, tl, nb.format_timeline_text(shadow(tl, {})))


def test_fallback_paths_are_sanitised():
    payload = next(e for e in EVENTS if "\n" in e["raw_message"] and "`" in e["raw_message"])["raw_message"]
    # Force the dispatcher to raise (non-numeric count) so the fallback string is used.
    out = nb.generate_alert_narrative({"failed_logins_last_5min": "x"}, {"type": "BRUTE_FORCE", "reason": payload})
    assert out.startswith("Narrative unavailable: ")
    assert payload not in out and "\n" not in out
    assert skeleton(out) == []

    out = nb.generate_investigative_summary(payload, {"first_seen": 5}, [], [], None)
    assert out.startswith("**Investigation report unavailable")
    assert payload not in out and "\n" not in out
    assert skeleton(out) == list("****")


def test_oversize_fields_are_capped_with_marker():
    big_user = next(e for e in EVENTS if len(e["effective_username"]) == 128 and e["effective_username"][0] == "a")
    out = nb.NarrativeBuilder.build(
        threat_type="Brute Force Attack",
        mitre_id="T1110.001",
        row_data={"source_ip": "192.0.2.24", "effective_username": big_user["effective_username"]},
    )
    assert big_user["effective_username"] not in out
    assert TRUNCATION_MARKER in out

    big_raw = next(e for e in EVENTS if len(e["raw_message"]) == 4096 and e["raw_message"].startswith("sshd"))
    out = nb.generate_alert_narrative({"source_ip": "192.0.2.24"}, {"type": "UNMAPPED", "reason": big_raw["raw_message"]})
    assert len(out) <= 200 + MAX_TEXT + len(TRUNCATION_MARKER)
    assert TRUNCATION_MARKER in out


def test_benign_narratives_are_unchanged_by_the_shield():
    """Plain values pass through untouched — the shield only bites on hostile input."""
    out = nb.generate_alert_narrative(
        {"source_ip": "198.51.100.37", "failed_logins_last_5min": 18, "login_attempt_velocity": 3.6},
        {"type": "BRUTE_FORCE"},
    )
    assert out.startswith("IP 198.51.100.37 performed 18 failed login attempts")


# ── static pin: every f-string interpolation in narrative_builder is safe ─

# Calls whose result is sanitised, numeric, or a template built by this module
# (whose own interpolations this test also checks).
_SAFE_CALLS = {"clean_field", "clean_list", "len", "int", "format_timeline_text", "get_shap_narrative_fragment"}
# Names/expressions built only from template constants — reviewed; extending
# either set is a security-review decision, not a test fix.
_TEMPLATE_INTERNAL = {"sev_emoji", "advice", "badge", "explanation", "lines", "r"}
_TEMPLATE_INTERNAL_EXPRS = {"'; '.join(signals)"}


def _func_assignments(func: ast.FunctionDef) -> Dict[str, List[ast.Assign]]:
    out: Dict[str, List[ast.Assign]] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    out.setdefault(tgt.id, []).append(node)
    return out


def _is_safe_expr(expr: ast.expr) -> bool:
    if isinstance(expr, (ast.Constant, ast.JoinedStr)):  # JoinedStr parts are checked on their own
        return True
    if isinstance(expr, ast.IfExp):
        return _is_safe_expr(expr.body) and _is_safe_expr(expr.orelse)
    if isinstance(expr, ast.BoolOp):
        return all(_is_safe_expr(v) for v in expr.values)
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Name):
            return expr.func.id in _SAFE_CALLS
        if (
            isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "join"
            and isinstance(expr.func.value, ast.Constant)
            and len(expr.args) == 1
            and isinstance(expr.args[0], (ast.GeneratorExp, ast.ListComp))
        ):
            return _is_safe_expr(expr.args[0].elt)
    return False


def test_every_interpolation_site_goes_through_the_shield():
    tree = ast.parse(Path(nb.__file__).read_text(encoding="utf-8"))
    offenders = []
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        assigned = _func_assignments(func)
        for node in ast.walk(func):
            if not isinstance(node, ast.FormattedValue):
                continue
            v = node.value
            if node.format_spec is not None or _is_safe_expr(v) or ast.unparse(v) in _TEMPLATE_INTERNAL_EXPRS:
                continue
            if isinstance(v, ast.Name):
                if v.id in _TEMPLATE_INTERNAL:
                    continue
                # The binding in force at this line must be sanitised.
                prior = [a for a in assigned.get(v.id, []) if a.lineno <= node.lineno]
                if prior and _is_safe_expr(max(prior, key=lambda a: a.lineno).value):
                    continue
            offenders.append(f"{func.name}:{node.lineno}: {ast.unparse(v)}")
    assert offenders == [], "unsanitised interpolation(s):\n" + "\n".join(offenders)
