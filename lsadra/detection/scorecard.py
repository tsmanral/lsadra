"""
Rules scorecard: how each registered rule does on the labelled demo corpus.

This scores the rule layer only, deterministically, with no trained model, so
it can run in CI and be committed per release (``docs/detection/scorecard.md``
and ``.json``). Model quality is measured separately by the detection bench
(``benchmarks/detection/``), on public labelled data.

Each corpus file is replayed per host (a host stands in for a device), with
features built over the whole file, which is what the live path sees once its
lookback window covers the scenario. An event "alerts" when its best rule match
is ``medium`` or above.

Regenerate after changing a rule::

    python scripts/detection_scorecard.py
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from lsadra.detection.attack_map import ATTACK_VERSION, get_technique
from lsadra.detection.event_types import OCSF_VERSION
from lsadra.detection.rule_engine import RULES, evaluate
from lsadra.features.feature_extractor import build_features
from lsadra.features.rule_features import build_rule_features

REPO = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO / "demo" / "corpus"
#: Scenario files that are fixtures for other tests, not detection scenarios.
NON_DETECTION_SCENARIOS = {"injection_attempts"}
ATTACK_LABELS = {"malicious", "suspicious"}


def _load(path: Path) -> List[Dict[str, Any]]:
    events = []
    with path.open(encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            if line.strip():
                ev = json.loads(line)
                ev["id"] = i
                ev["device_id"] = ev.get("host") or "demo-device"
                events.append(ev)
    return events


def _same_technique(named: str, truth: Any) -> bool:
    """Exact match, or one is the parent of the other (T1110 vs T1110.001)."""
    if not named or not truth or named == "N/A":
        return False
    return named == truth or named.split(".")[0] == str(truth).split(".")[0]


def score_scenario(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-event results: label, ground-truth technique, best match, all matches."""
    out: List[Dict[str, Any]] = []
    by_device: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ev in events:
        by_device[ev["device_id"]].append(ev)
    for device_events in by_device.values():
        df = build_features(device_events)
        if df.empty:
            continue
        df = build_rule_features(df)
        truth = {ev["id"]: ev.get("attributes", {}).get("ground_truth", {}) for ev in device_events}
        for row in df.to_dict(orient="records"):
            gt = truth.get(int(row["id"]), {})
            matches = evaluate(row)
            best = matches[0] if matches else None
            out.append({
                "id": int(row["id"]),
                "label": gt.get("label", "benign"),
                "truth_technique": gt.get("attack_technique"),
                "alert": bool(best and best.raises_alert),
                "best_rule": best.rule.id if best else None,
                "best_level": best.level if best else None,
                "technique": best.technique.id if best else None,
                "matches": [m.rule.id for m in matches],
            })
    return sorted(out, key=lambda r: r["id"])


def build_scorecard(corpus_dir: Path = CORPUS_DIR) -> Dict[str, Any]:
    """Score every corpus file and every rule. Pure function of corpus + rules."""
    scenarios: Dict[str, Any] = {}
    per_rule: Dict[str, Dict[str, Any]] = {
        rid: {"alerts_on_attack_events": 0, "alerts_on_benign_events": 0,
              "label_only_matches": 0, "scenarios": set()}
        for rid in RULES
    }
    for path in sorted(corpus_dir.glob("*.jsonl")):
        name = path.stem
        results = score_scenario(_load(path))
        attack = [r for r in results if r["label"] in ATTACK_LABELS]
        benign = [r for r in results if r["label"] not in ATTACK_LABELS]
        detected = [r for r in attack if r["alert"]]
        entry = {
            "events": len(results),
            "attack_events": len(attack),
            "benign_events": len(benign),
            "attack_events_alerted": len(detected),
            "benign_events_alerted": sum(r["alert"] for r in benign),
            "technique_named_correctly": sum(
                _same_technique(r["technique"] or "", r["truth_technique"]) for r in detected),
            "detected": bool(detected),
            "detection_scenario": name not in NON_DETECTION_SCENARIOS,
        }
        scenarios[name] = entry
        for r in results:
            for rid in r["matches"]:
                per_rule[rid]["scenarios"].add(name)
            if r["best_rule"] is None:
                continue
            stats = per_rule[r["best_rule"]]
            if not r["alert"]:
                stats["label_only_matches"] += 1
            elif r["label"] in ATTACK_LABELS:
                stats["alerts_on_attack_events"] += 1
            else:
                stats["alerts_on_benign_events"] += 1

    rules_out = {}
    for rid, rule in RULES.items():
        stats = per_rule[rid]
        tech = get_technique(rule.technique_ids[0])
        rules_out[rid] = {
            "title": rule.title, "version": rule.version, "status": rule.status,
            "level": rule.level, "techniques": list(rule.technique_ids),
            "tactics": [t.name for t in tech.tactics] if tech else [],
            "evaluated_by": rule.evaluated_by, "corpus_scenario": rule.scenario,
            "alerts_on_attack_events": stats["alerts_on_attack_events"],
            "alerts_on_benign_events": stats["alerts_on_benign_events"],
            "label_only_matches": stats["label_only_matches"],
            "fired_in": sorted(stats["scenarios"]),
        }
    det = [s for s in scenarios.values() if s["detection_scenario"]]
    return {
        "attack_version": ATTACK_VERSION,
        "ocsf_version": OCSF_VERSION,
        "rule_count": len(RULES),
        "summary": {
            "attack_events": sum(s["attack_events"] for s in det),
            "attack_events_alerted": sum(s["attack_events_alerted"] for s in det),
            "benign_events": sum(s["benign_events"] for s in det),
            "benign_events_alerted": sum(s["benign_events_alerted"] for s in det),
            "scenarios_detected": sum(1 for s in det if s["attack_events"] and s["detected"]),
            "scenarios_with_attacks": sum(1 for s in det if s["attack_events"]),
        },
        "scenarios": scenarios,
        "rules": rules_out,
    }


def render_markdown(card: Dict[str, Any]) -> str:
    """The committed human-readable scorecard."""
    s = card["summary"]
    lines = [
        "# Detection rules scorecard",
        "",
        "Generated by `python scripts/detection_scorecard.py` from the labelled demo corpus "
        "(`demo/corpus/`). It scores the **rule layer only**, with no trained model; model "
        "quality is measured by the detection bench on public data. CI fails when this file "
        "is out of date.",
        "",
        f"ATT&CK Enterprise {card['attack_version']} · OCSF {card['ocsf_version']} · "
        f"{card['rule_count']} rules",
        "",
        "An event *alerts* when its best rule match is `medium` or higher; `low` matches only "
        "name the technique of an event the anomaly layers flag.",
        "",
        "## Summary",
        "",
        f"- Scenarios detected: {s['scenarios_detected']} of {s['scenarios_with_attacks']}",
        f"- Attack events alerted: {s['attack_events_alerted']} of {s['attack_events']} "
        "(an attack usually needs one alert, not one per event)",
        f"- Benign events alerted (false positives): {s['benign_events_alerted']} of "
        f"{s['benign_events']}",
        "",
        "## Scenarios",
        "",
        "| Scenario | Events | Attack events | Alerted | Technique named | Benign alerted |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, sc in card["scenarios"].items():
        note = "" if sc["detection_scenario"] else " (R8 fixture)"
        lines.append(
            f"| `{name}`{note} | {sc['events']} | {sc['attack_events']} | "
            f"{sc['attack_events_alerted']} | {sc['technique_named_correctly']} | "
            f"{sc['benign_events_alerted']} |"
        )
    lines += [
        "",
        "## Rules",
        "",
        "| Rule | Level | Status | ATT&CK | Tactics | Alerts on attacks | Alerts on benign | "
        "Label-only | Corpus coverage |",
        "|---|---|---|---|---|---:|---:|---:|---|",
    ]
    for rid, r in card["rules"].items():
        if r["evaluated_by"] != "event":
            coverage = f"run by the {r['evaluated_by']}; unit tests only"
        elif r["corpus_scenario"]:
            coverage = f"`{r['corpus_scenario']}`"
        else:
            coverage = "no corpus scenario yet; unit tests only"
        lines.append(
            f"| `{rid}` v{r['version']} | {r['level']} | {r['status']} | "
            f"{', '.join(r['techniques'])} | {', '.join(r['tactics'])} | "
            f"{r['alerts_on_attack_events']} | {r['alerts_on_benign_events']} | "
            f"{r['label_only_matches']} | {coverage} |"
        )
    return "\n".join(lines) + "\n"


def write(out_dir: Path) -> Dict[str, Any]:
    card = build_scorecard()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scorecard.json").write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")
    (out_dir / "scorecard.md").write_text(render_markdown(card), encoding="utf-8")
    return card


def as_frame(card: Dict[str, Any]) -> pd.DataFrame:
    """Rules table as a DataFrame (for notebooks)."""
    return pd.DataFrame.from_dict(card["rules"], orient="index")
