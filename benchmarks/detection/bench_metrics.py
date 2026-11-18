"""
Scoring for the detection bench.

Rates are computed on the test period only. Negatives are benign events;
positives are attack events labelled with an ATT&CK technique; context events
(the non-attack noise inside a public attack capture) count for neither.

For each continuous score the threshold for a target false-positive rate *f*
is the smallest value that flags at most ``floor(f * n_negatives)`` benign
events (strictly greater than the threshold counts as flagged). Ties make the
achieved FPR lower than the target, so the achieved value is always reported.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional

NEG_INF = float("-inf")


def threshold_for_fpr(neg_scores: List[float], fpr: float) -> float:
    """Threshold t such that #(neg > t) <= floor(fpr * n)."""
    if not neg_scores:
        return NEG_INF
    ordered = sorted(neg_scores, reverse=True)
    allowed = int(math.floor(fpr * len(ordered)))
    if allowed >= len(ordered):
        return NEG_INF
    return ordered[allowed]


def _rate(hit: int, n: int) -> Optional[float]:
    return round(hit / n, 4) if n else None


def score_at_fpr(records: List[Dict[str, Any]], key: str, fpr: float) -> Dict[str, Any]:
    neg = [r[key] for r in records if r["role"] == "negative"]
    pos = [r for r in records if r["role"] == "positive"]
    t = threshold_for_fpr(neg, fpr)
    false_pos = sum(1 for s in neg if s > t)
    achieved = false_pos / len(neg) if neg else 0.0

    by_tech: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in pos:
        by_tech[r["technique"]].append(r)

    techniques = {}
    for tech in sorted(by_tech):
        rows = by_tech[tech]
        instances: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for r in rows:
            instances[r["instance"]].append(r)
        inst_out = {}
        for inst in sorted(instances):
            irows = instances[inst]
            hits = sum(1 for r in irows if r[key] > t)
            inst_out[inst] = {
                "positive_events": len(irows),
                "events_detected": hits,
                "detected": hits > 0,
                # Probability that a score with no signal would still flag at
                # least one of these events at this FPR.
                "chance_detect": round(1 - (1 - achieved) ** len(irows), 4),
            }
        ev_hits = sum(1 for r in rows if r[key] > t)
        techniques[tech] = {
            "positive_events": len(rows),
            "event_tpr": _rate(ev_hits, len(rows)),
            "instances": len(instances),
            "instance_tpr": _rate(sum(1 for v in inst_out.values() if v["detected"]), len(instances)),
            "instance_detail": inst_out,
        }

    all_hits = sum(1 for r in pos if r[key] > t)
    return {
        "target_fpr": fpr,
        "threshold": None if t == NEG_INF else round(t, 6),
        "achieved_fpr": round(achieved, 6),
        "false_positives": false_pos,
        # Mass sitting exactly on the threshold: a score that saturates (many
        # benign events tied at its maximum) cannot reach the target FPR.
        "negatives_at_threshold": sum(1 for s in neg if s == t),
        "positives_at_threshold": sum(1 for r in pos if r[key] == t),
        "event_tpr": _rate(all_hits, len(pos)),
        "techniques": techniques,
    }


def verdict_metrics(records: List[Dict[str, Any]], host_days: int) -> Dict[str, Any]:
    """The pipeline's own is_anomaly verdict, as deployed."""
    neg = [r for r in records if r["role"] == "negative"]
    pos = [r for r in records if r["role"] == "positive"]
    fp = sum(1 for r in neg if r["is_anomaly"])
    by_tech: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in pos:
        by_tech[r["technique"]].append(r)
    alerts = [r for r in records if r["is_anomaly"]]
    return {
        "fpr": _rate(fp, len(neg)),
        "event_tpr": _rate(sum(1 for r in pos if r["is_anomaly"]), len(pos)),
        "alerts_per_host_day_benign": round(fp / host_days, 2) if host_days else None,
        "alerts_per_host_day_total": round(len(alerts) / host_days, 2) if host_days else None,
        "techniques": {
            t: {
                "positive_events": len(rows),
                "event_tpr": _rate(sum(1 for r in rows if r["is_anomaly"]), len(rows)),
                "instance_tpr": _rate(
                    sum(1 for inst in {r["instance"] for r in rows}
                        if any(r["is_anomaly"] for r in rows if r["instance"] == inst)),
                    len({r["instance"] for r in rows}),
                ),
            }
            for t, rows in sorted(by_tech.items())
        },
        # Which ATT&CK label the rule engine put on each alert.
        "alert_labels": dict(Counter(r["mitre_technique"] for r in alerts).most_common(12)),
        # Of the alerts on attack events, how many carry that event's technique.
        "label_matches_technique": _rate(
            sum(1 for r in pos if r["is_anomaly"] and r["mitre_technique"] == r["technique"]),
            sum(1 for r in pos if r["is_anomaly"]),
        ),
    }


def summarize(records: Iterable[Dict[str, Any]], score_keys: List[str], fprs: List[float],
              host_days: int) -> Dict[str, Any]:
    records = list(records)
    counts = Counter(r["role"] for r in records)
    return {
        "events": dict(counts),
        "unscored": sum(1 for r in records if not r["scored"]),
        "host_days": host_days,
        "deployed_verdict": verdict_metrics(records, host_days),
        "scores": {
            key: {f"{f:g}": score_at_fpr(records, key, f) for f in fprs}
            for key in score_keys
        },
        "alerts_per_host_day_at_fpr": {
            f"{f:g}": round(f * counts.get("negative", 0) / host_days, 2) if host_days else None
            for f in fprs
        },
    }
