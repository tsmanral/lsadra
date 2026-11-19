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


def score_sigma(corpus_dir: Path = CORPUS_DIR) -> Dict[str, Any]:
    """
    The Sigma layer on the same corpus (audit G-28). It runs in shadow mode in
    production, so these numbers are what it *would* add if switched to alert.
    """
    from lsadra.detection.sigma_engine import SigmaEngine

    engine = SigmaEngine()
    scenarios: Dict[str, Any] = {}
    fired: Dict[str, Dict[str, Any]] = {}
    for path in sorted(corpus_dir.glob("*.jsonl")):
        events = _load(path)
        by_device: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in events:
            by_device[ev["device_id"]].append(ev)
        attack = benign = attack_hit = benign_hit = 0
        for device_events in by_device.values():
            df = build_features(device_events)
            if df.empty:
                continue
            rows = build_rule_features(df).to_dict(orient="records")
            truth = {ev["id"]: ev.get("attributes", {}).get("ground_truth", {})
                     for ev in device_events}
            for row, hits in zip(rows, engine.evaluate_frame(rows)):
                label = truth.get(int(row["id"]), {}).get("label", "benign")
                alerting = [h for h in hits if h.raises_alert]
                is_attack = label in ATTACK_LABELS
                attack += is_attack
                benign += not is_attack
                attack_hit += bool(alerting) and is_attack
                benign_hit += bool(alerting) and not is_attack
                for h in hits:
                    entry = fired.setdefault(h.rule_id, {
                        "title": h.title, "level": h.level, "source": h.source,
                        "techniques": list(h.technique_ids), "attack_events": 0,
                        "benign_events": 0, "scenarios": set()})
                    entry["attack_events" if is_attack else "benign_events"] += 1
                    entry["scenarios"].add(path.stem)
        scenarios[path.stem] = {
            "attack_events": attack, "attack_events_matched": attack_hit,
            "benign_events": benign, "benign_events_matched": benign_hit,
            "detection_scenario": path.stem not in NON_DETECTION_SCENARIOS,
        }
    for entry in fired.values():
        entry["scenarios"] = sorted(entry["scenarios"])
    det = [v for v in scenarios.values() if v["detection_scenario"]]
    return {
        "rules_loaded": len(engine.rules) + len(engine.correlations),
        "sigmahq_rules": sum(1 for v in engine._source.values() if v == "sigmahq"),
        "filters": len(engine.filters),
        "summary": {
            "scenarios_detected": sum(1 for v in det if v["attack_events_matched"]),
            "scenarios_with_attacks": sum(1 for v in det if v["attack_events"]),
            "benign_events_matched": sum(v["benign_events_matched"] for v in det),
            "benign_events": sum(v["benign_events"] for v in det),
        },
        "scenarios": scenarios,
        "rules_fired": dict(sorted(fired.items(), key=lambda kv: kv[1]["title"])),
    }


def score_risk(corpus_dir: Path = CORPUS_DIR) -> Dict[str, Any]:
    """
    Entity risk on the same corpus (audit G-29): the highest host and user
    score each scenario reaches from built-in rule and Sigma signals, and
    whether it would open a risk case. Shadow mode in production.
    """
    from lsadra.detection.risk import (
        DEFAULT_HALF_LIFE_HOURS,
        DEFAULT_THRESHOLD,
        DEFAULT_WINDOW_DAYS,
        risk_rows,
        score_entity,
    )
    from lsadra.detection.sigma_engine import SigmaEngine

    engine = SigmaEngine()
    out: Dict[str, Any] = {}
    for path in sorted(corpus_dir.glob("*.jsonl")):
        by_device: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in _load(path):
            by_device[ev["device_id"]].append(ev)
        results: List[Dict[str, Any]] = []
        for device_events in by_device.values():
            df = build_features(device_events)
            if df.empty:
                continue
            rows = build_rule_features(df).to_dict(orient="records")
            for row, hits in zip(rows, engine.evaluate_frame(rows)):
                results.append({
                    "event_id": int(row["id"]), "device_id": row.get("device_id"),
                    "host": row.get("host"), "effective_username": row.get("effective_username"),
                    "event_type": row.get("canonical_event_type"),
                    "created_at": str(row.get("timestamp")),
                    "rule_hits": [{"rule_id": m.rule.id, "title": m.rule.title, "level": m.level,
                                   "technique": m.technique.id, "tactics": m.tactics}
                                  for m in evaluate(row)],
                    "sigma_matches": [h.as_dict() for h in hits],
                })
        by_entity: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
        for r in risk_rows(results):
            by_entity[(r["entity_type"], r["entity"])].append(r)
        best: Dict[str, Any] = {"host": 0.0, "user": 0.0}
        cases: List[Dict[str, Any]] = []
        for (etype, entity), events in sorted(by_entity.items()):
            card = score_entity(events, window_days=DEFAULT_WINDOW_DAYS,
                                half_life_hours=DEFAULT_HALF_LIFE_HOURS)
            best[etype] = max(best[etype], card["score"])
            if card["score"] >= DEFAULT_THRESHOLD:
                cases.append({"entity_type": etype, "entity": entity, "score": card["score"],
                              "tactics": card["tactics"]})
        out[path.stem] = {"max_host_score": best["host"], "max_user_score": best["user"],
                          "cases": cases,
                          "detection_scenario": path.stem not in NON_DETECTION_SCENARIOS}
    return {"threshold": DEFAULT_THRESHOLD, "scenarios": out}


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
        "sigma": score_sigma(corpus_dir),
        "risk": score_risk(corpus_dir),
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
    sg = card.get("sigma")
    if sg:
        ss = sg["summary"]
        lines += [
            "",
            "## Sigma layer (shadow mode)",
            "",
            f"{sg['rules_loaded']} Sigma rules ({sg['sigmahq_rules']} from SigmaHQ) and "
            f"{sg['filters']} suppression filter(s). The layer runs in shadow mode by default "
            "(`LSADRA_SIGMA_MODE`), so these matches are recorded but raise no alerts. A match "
            "counts here when its level is `medium` or higher.",
            "",
            f"- Scenarios matched: {ss['scenarios_detected']} of {ss['scenarios_with_attacks']}",
            f"- Benign events matched (would-be false positives): "
            f"{ss['benign_events_matched']} of {ss['benign_events']}",
            "",
            "| Scenario | Attack events matched | Benign events matched |",
            "|---|---:|---:|",
        ]
        for name, sc in sg["scenarios"].items():
            note = "" if sc["detection_scenario"] else " (R8 fixture)"
            lines.append(
                f"| `{name}`{note} | {sc['attack_events_matched']} of {sc['attack_events']} | "
                f"{sc['benign_events_matched']} of {sc['benign_events']} |"
            )
        lines += [
            "",
            "| Sigma rule | Source | Level | ATT&CK | Attack events | Benign events | Scenarios |",
            "|---|---|---|---|---:|---:|---|",
        ]
        for r in sg["rules_fired"].values():
            lines.append(
                f"| {r['title']} | {r['source']} | {r['level']} | {', '.join(r['techniques'])} | "
                f"{r['attack_events']} | {r['benign_events']} | "
                f"{', '.join(f'`{x}`' for x in r['scenarios'])} |"
            )
        lines.append("")
        lines.append("Sigma rules not listed did not match any corpus event; "
                     "`tests/test_sigma_engine.py` covers them with curated events.")
    rk = card.get("risk")
    if rk:
        lines += [
            "",
            "## Entity risk (shadow mode)",
            "",
            "Rule and Sigma signals added up per host and user (`lsadra/detection/risk.py`): "
            f"a score of {rk['threshold']:.0f} or more opens a risk case. The layer runs in "
            "shadow mode by default (`LSADRA_RISK_MODE`).",
            "",
            "| Scenario | Highest host score | Highest user score | Risk cases (tactic chain) |",
            "|---|---:|---:|---|",
        ]
        for name, sc in rk["scenarios"].items():
            note = "" if sc["detection_scenario"] else " (R8 fixture)"
            cases = "; ".join(
                f"{c['entity_type']} `{c['entity']}` {c['score']:.0f}: {' -> '.join(c['tactics'])}"
                for c in sc["cases"]) or "none"
            lines.append(f"| `{name}`{note} | {sc['max_host_score']:.1f} | "
                         f"{sc['max_user_score']:.1f} | {cases} |")
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
