"""
Entity risk scoring and risk cases (audit G-29, ADR 0007 layer 5).

Single events rarely prove an attack; several weak signals on the same host or
user usually do. Every detection signal (a built-in rule match, a Sigma match,
or an anomaly no rule explained) is stored as a ``risk_events`` row for the
event's host and for its user. An entity's score is computed from its signals
of the last ``LSADRA_RISK_WINDOW_DAYS``:

1. Each signal has base points by level (``LEVEL_POINTS``; anomalies with no
   rule get a few points by severity).
2. One event counts once (its strongest signal, when several rules match it),
   and the same rule on the same entity counts once per hour (its highest
   points), so a 500-line brute force is one signal per hour, not 500.
   Failed logins add risk to the host only: the account they name is usually
   the target, not the attacker.
3. Points decay with a half-life of ``LSADRA_RISK_HALF_LIFE_HOURS``, measured
   from the entity's newest signal (event time, so replayed logs score the
   same as live ones).
4. Distinct ATT&CK tactics multiply the sum: x1.25 per tactic after the first,
   capped at x2. Credential access followed by persistence and exfiltration
   is worth more than the same points from one tactic.
5. The user-set asset weight (``asset_weights``, default 1, at most 5)
   multiplies the result.
6. The total maps to 0-100 with ``100 * (1 - exp(-total / 60))``: one ``high``
   signal scores about 33, and a ``high`` plus a ``medium`` in two tactics
   about 53. A chain across three tactics crosses the default threshold of 70.
   These constants are a starting point for the detection bench to tune.

A score at or above ``LSADRA_RISK_THRESHOLD`` opens a *risk case*
(``risk_notables``) for the entity, or updates its open case: the case holds
the score, the ordered tactic chain and the signal count, and its timeline is
the entity's ``risk_events``. ``LSADRA_RISK_MODE`` gates the layer:

- ``shadow`` (default): signals, scores and cases are recorded, nothing alerts.
- ``alert``: when a case opens, the event that crossed the threshold also
  raises an alert (``threat_type`` "Entity risk threshold crossed").
- ``off``: nothing is recorded.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from lsadra.explainability.sanitize import clean_field

logger = logging.getLogger(__name__)

MODES = ("off", "shadow", "alert")
ENTITY_TYPES = ("host", "user")
LEVEL_POINTS = {"informational": 0.0, "low": 4.0, "medium": 12.0, "high": 24.0, "critical": 40.0}
ANOMALY_POINTS = {"LOW": 2.0, "MEDIUM": 3.0, "HIGH": 6.0, "CRITICAL": 8.0}
SCALE = 60.0
TACTIC_BONUS = 0.25
MAX_TACTIC_MULTIPLIER = 2.0
DEDUP_SECONDS = 3600
DEFAULT_WEIGHT = 1.0
MAX_WEIGHT = 5.0
RISK_THREAT_TYPE = "Entity risk threshold crossed"
# Defaults of LSADRA_RISK_THRESHOLD / _WINDOW_DAYS / _HALF_LIFE_HOURS (config.py).
DEFAULT_THRESHOLD = 70.0
DEFAULT_WINDOW_DAYS = 7
DEFAULT_HALF_LIFE_HOURS = 24.0
_IGNORED_USERS = {"", "unknown", "none", "n/a", "-"}


def risk_mode() -> str:
    from lsadra.config import RISK_MODE

    return RISK_MODE if RISK_MODE in MODES else "shadow"


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        ts = value
    else:
        text = str(value or "").strip()
        try:
            ts = datetime.fromisoformat(text.replace(" ", "T", 1)) if text else None
        except ValueError:
            ts = None
        if ts is None:
            return datetime.now(timezone.utc)
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def iso_utc(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


# ── signals ─────────────────────────────────────────────────────────────────


def entities_of(result: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    The (entity_type, entity) pairs a detection result belongs to.

    A failed login names the account that was *tried*, which is usually the
    victim, not the actor, so it adds risk to the host only.
    """
    out: List[Tuple[str, str]] = []
    host = str(result.get("host") or result.get("device_id") or "").strip()
    if host:
        out.append(("host", host))
    if result.get("event_type") == "auth_failure":
        return out
    user = str(result.get("effective_username") or "").strip()
    if user.lower() not in _IGNORED_USERS:
        out.append(("user", user))
    return out


def signals_of(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Risk signals in one detection result, before they are tied to entities."""
    signals: List[Dict[str, Any]] = []
    for hit in result.get("rule_hits") or []:
        points = LEVEL_POINTS.get(str(hit.get("level")), 0.0)
        if points > 0:
            signals.append(
                {
                    "source": "rule",
                    "rule_id": hit.get("rule_id"),
                    "title": hit.get("title", ""),
                    "level": hit.get("level"),
                    "technique_id": hit.get("technique"),
                    "tactics": list(hit.get("tactics") or []),
                    "base_score": points,
                }
            )
    for hit in result.get("sigma_matches") or []:
        points = LEVEL_POINTS.get(str(hit.get("level")), 0.0)
        if points > 0:
            techniques = list(hit.get("techniques") or [])
            signals.append(
                {
                    "source": "sigma",
                    "rule_id": f"sigma:{hit.get('rule_id')}",
                    "title": hit.get("title", ""),
                    "level": hit.get("level"),
                    "technique_id": techniques[0] if techniques else None,
                    "tactics": list(hit.get("tactics") or []),
                    "base_score": points,
                }
            )
    if result.get("is_anomaly") and not signals:
        label = str(result.get("severity_label") or "LOW")
        signals.append(
            {
                "source": "anomaly",
                "rule_id": None,
                "title": "Unmapped anomaly",
                "level": label.lower(),
                "technique_id": None,
                "tactics": [],
                "base_score": ANOMALY_POINTS.get(label, ANOMALY_POINTS["LOW"]),
            }
        )
    return signals


def risk_rows(results: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """``risk_events`` rows for a batch of detection results."""
    rows: List[Dict[str, Any]] = []
    for idx, res in enumerate(results):
        signals = signals_of(res)
        if not signals:
            continue
        when = iso_utc(parse_time(res.get("created_at")))
        for etype, entity in entities_of(res):
            for sig in signals:
                rows.append(
                    dict(
                        sig,
                        entity_type=etype,
                        entity=entity,
                        device_id=str(res.get("device_id") or ""),
                        user_id=str(res.get("user_id") or "") or None,
                        event_id=res.get("event_id"),
                        event_time=when,
                        result_index=idx,
                    )
                )
    return rows


# ── scoring ─────────────────────────────────────────────────────────────────


def score_entity(
    events: List[Dict[str, Any]],
    weight: float = DEFAULT_WEIGHT,
    now: Optional[datetime] = None,
    window_days: Optional[int] = None,
    half_life_hours: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Score one entity from its risk events. Pure: no storage, no clock unless
    *now* is omitted and there are no events.
    """
    if window_days is None or half_life_hours is None:
        from lsadra.config import RISK_HALF_LIFE_HOURS, RISK_WINDOW_DAYS

        window_days = window_days or RISK_WINDOW_DAYS
        half_life_hours = half_life_hours or RISK_HALF_LIFE_HOURS
    half_life = half_life_hours
    weight = min(max(float(weight or DEFAULT_WEIGHT), 0.0), MAX_WEIGHT)
    timed = sorted(((parse_time(e["event_time"]), e) for e in events), key=lambda p: p[0])
    if now is None:
        now = timed[-1][0] if timed else datetime.now(timezone.utc)
    start = now - timedelta(days=window_days)
    timed = [(t, e) for t, e in timed if start <= t <= now]

    # One event is one piece of evidence: when several rules match the same
    # event, only its strongest signal adds points (all of them add tactics).
    strongest: Dict[Any, Tuple[datetime, Dict[str, Any]]] = {}
    for n, (t, e) in enumerate(timed):
        ev_key = (
            ("event", e.get("device_id"), e["event_id"])
            if e.get("event_id") is not None
            else ("row", n)
        )
        if ev_key not in strongest or float(e["base_score"]) > float(
            strongest[ev_key][1]["base_score"]
        ):
            strongest[ev_key] = (t, e)

    best: Dict[Tuple[str, str, int], Tuple[datetime, Dict[str, Any]]] = {}
    for t, e in strongest.values():
        key = (
            e["source"],
            str(e.get("rule_id") or e.get("title")),
            int(t.timestamp()) // DEDUP_SECONDS,
        )
        if key not in best or float(e["base_score"]) > float(best[key][1]["base_score"]):
            best[key] = (t, e)

    raw = 0.0
    for t, e in best.values():
        age_h = (now - t).total_seconds() / 3600.0
        raw += float(e["base_score"]) * 0.5 ** (age_h / half_life)

    tactics: List[str] = []
    for _, e in timed:
        for tactic in e.get("tactics") or []:
            if tactic not in tactics:
                tactics.append(tactic)
    multiplier = min(MAX_TACTIC_MULTIPLIER, 1.0 + TACTIC_BONUS * max(len(tactics) - 1, 0))
    total = raw * multiplier * weight
    return {
        "score": round(100.0 * (1.0 - math.exp(-total / SCALE)), 1),
        "points": round(raw, 2),
        "tactic_multiplier": multiplier,
        "weight": weight,
        "tactics": tactics,
        "signals": len(best),
        "first_seen": iso_utc(timed[0][0]) if timed else None,
        "last_seen": iso_utc(timed[-1][0]) if timed else None,
    }


def case_narrative(etype: str, entity: str, card: Dict[str, Any]) -> str:
    """Plain-text summary of a risk case; every event-derived value is sanitised."""
    chain = " -> ".join(clean_field(t) for t in card["tactics"]) or "no ATT&CK tactic"
    return (
        f"{clean_field(etype).capitalize()} {clean_field(entity)} reached a risk score of "
        f"{card['score']:.0f}/100 from {int(card['signals'])} signal(s) since "
        f"{clean_field(card['first_seen'] or '')}. Tactic chain: {chain}."
    )


# ── recording ───────────────────────────────────────────────────────────────


def record(results: List[Dict[str, Any]], mode: str) -> List[Dict[str, Any]]:
    """
    Store the batch's risk signals, rescore every entity they touch, and open
    or update risk cases. Returns the cases this batch *opened*, each with the
    ``result_index`` of the event that crossed the threshold.

    Each touched entity's latest score is also set on its results as
    ``risk_scores`` (``{"host": .., "user": ..}``).
    """
    from lsadra.config import RISK_THRESHOLD, RISK_WINDOW_DAYS
    from lsadra.storage.database import (
        create_risk_notable,
        get_asset_weight,
        get_open_risk_notable,
        get_risk_events,
        insert_risk_events,
        update_risk_notable,
    )

    rows = risk_rows(results)
    if not rows:
        return []
    insert_risk_events(rows)

    last_index: Dict[Tuple[str, str], int] = {}
    owner: Dict[Tuple[str, str], Tuple[str, Optional[str]]] = {}
    newest: Dict[Tuple[str, str], str] = {}
    for r in rows:
        key = (r["entity_type"], r["entity"])
        last_index[key] = max(last_index.get(key, -1), r["result_index"])
        owner[key] = (r["device_id"], r["user_id"])
        newest[key] = max(newest.get(key, ""), r["event_time"])

    opened: List[Dict[str, Any]] = []
    for key, idx in last_index.items():
        etype, entity = key
        now = parse_time(newest[key])
        since = iso_utc(now - timedelta(days=RISK_WINDOW_DAYS))
        card = score_entity(
            get_risk_events(etype, entity, since=since),
            weight=get_asset_weight(etype, entity),
            now=now,
        )
        for res in results:
            if (etype, entity) in entities_of(res):
                res.setdefault("risk_scores", {})[etype] = card["score"]
        if card["score"] < RISK_THRESHOLD:
            continue
        device_id, user_id = owner[key]
        case = get_open_risk_notable(etype, entity)
        if case:
            update_risk_notable(
                case["id"], card["score"], card["tactics"], card["signals"], card["last_seen"]
            )
            continue
        case_id = create_risk_notable(
            etype,
            entity,
            device_id,
            user_id,
            card["score"],
            card["tactics"],
            card["signals"],
            mode,
            card["first_seen"],
            card["last_seen"],
        )
        opened.append(
            {"id": case_id, "entity_type": etype, "entity": entity, "result_index": idx, **card}
        )
    return opened


def raise_case_alerts(results: List[Dict[str, Any]], opened: List[Dict[str, Any]]) -> None:
    """Alert mode: turn the event that opened each case into an alert."""
    from lsadra.detection.severity import apply_rule_floor

    for case in opened:
        res = results[case["result_index"]]
        res.setdefault("risk_cases", []).append(case["id"])
        if res.get("is_anomaly"):
            continue  # already an alert; the case is linked above
        score, label = apply_rule_floor(
            float(res.get("severity_score") or 0.0), str(res.get("severity_label") or "LOW"), "HIGH"
        )
        res.update(
            {
                "is_anomaly": True,
                "threat_type": RISK_THREAT_TYPE,
                "attack_type": RISK_THREAT_TYPE,
                "severity_score": score,
                "severity_label": label,
                "rule_id": f"risk:{case['entity_type']}",
                "mitre_tactics": case["tactics"],
                "narrative": case_narrative(case["entity_type"], case["entity"], case),
            }
        )
