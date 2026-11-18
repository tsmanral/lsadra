"""
Entity risk scoring (audit G-29): signals add up per host and user with decay,
a bonus for distinct ATT&CK tactics and a user-set asset weight; crossing the
threshold opens a risk case with an ordered tactic chain. Shadow by default.
"""

from datetime import datetime, timedelta, timezone

import pytest

import lsadra.config as config
import lsadra.storage.database as database
from lsadra.detection import detection_orchestrator as orch_mod
from lsadra.detection import risk
from lsadra.detection.risk import entities_of, score_entity, signals_of
from tests.test_live_rules import _run, orchestrator, store  # noqa: F401

T0 = datetime(2026, 1, 15, 2, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "risk.db"
    monkeypatch.setattr(config, "DB_PATH", path)
    monkeypatch.setattr(database, "DB_PATH", path)
    database.init_db()
    return database


def _ev(hours=0.0, level="high", points=None, rule="r1", tactics=("Credential Access",),
        source="rule"):
    return {"event_time": (T0 + timedelta(hours=hours)).isoformat(), "source": source,
            "rule_id": rule, "title": rule, "level": level, "tactics": list(tactics),
            "base_score": points if points is not None else risk.LEVEL_POINTS[level]}


# ── scoring (pure) ──────────────────────────────────────────────────────────

def test_one_high_signal_scores_about_a_third():
    card = score_entity([_ev()])
    assert 30 <= card["score"] <= 36
    assert card["signals"] == 1 and card["tactics"] == ["Credential Access"]


def test_the_same_rule_counts_once_per_hour():
    burst = [_ev(hours=i / 100) for i in range(40)]  # 40 hits inside one hour
    card = score_entity(burst)
    assert card["signals"] == 1
    assert card["score"] <= score_entity([_ev()])["score"]
    assert score_entity([_ev(0), _ev(1.5)])["signals"] == 2


def test_one_event_matching_several_rules_counts_once():
    same_event = [dict(_ev(rule=r, tactics=(t,)), event_id=5, device_id="d")
                  for r, t in (("a", "Credential Access"), ("b", "Initial Access"))]
    card = score_entity(same_event)
    assert card["points"] == pytest.approx(24.0)
    assert card["tactics"] == ["Credential Access", "Initial Access"]


def test_points_decay_with_the_half_life():
    old_then_new = [_ev(0, rule="a"), _ev(24, rule="b", points=0.0001)]
    card = score_entity(old_then_new, half_life_hours=24)
    assert card["points"] == pytest.approx(12.0, abs=0.01)


def test_signals_outside_the_window_do_not_count():
    card = score_entity([_ev(0, rule="a"), _ev(24 * 8, rule="b", level="low")], window_days=7)
    assert card["signals"] == 1 and card["points"] == pytest.approx(4.0)


def test_distinct_tactics_raise_the_score_and_keep_their_order():
    one = score_entity([_ev(0, rule="a"), _ev(1, rule="b")])
    chain = score_entity([
        _ev(0, rule="a", tactics=("Credential Access",)),
        _ev(1, rule="b", tactics=("Persistence",)),
    ])
    assert chain["score"] > one["score"]
    assert chain["tactic_multiplier"] == 1.25
    assert chain["tactics"] == ["Credential Access", "Persistence"]
    many = score_entity([_ev(i, rule=str(i), tactics=(f"T{i}",)) for i in range(9)])
    assert many["tactic_multiplier"] == risk.MAX_TACTIC_MULTIPLIER


def test_a_three_tactic_chain_crosses_the_default_threshold():
    card = score_entity([
        _ev(0, rule="a", tactics=("Credential Access",)),
        _ev(1, rule="b", tactics=("Persistence",)),
        _ev(2, rule="c", level="medium", tactics=("Collection",)),
    ])
    assert card["score"] >= 70


def test_asset_weight_multiplies_and_is_capped():
    base = score_entity([_ev()])["score"]
    assert score_entity([_ev()], weight=3)["score"] > base
    assert score_entity([_ev()], weight=50)["weight"] == risk.MAX_WEIGHT


def test_score_stays_below_100():
    card = score_entity([_ev(i, rule=str(i), level="critical", tactics=(f"T{i}",))
                         for i in range(50)], weight=5)
    assert 99 <= card["score"] <= 100


# ── signals ─────────────────────────────────────────────────────────────────

def test_signals_include_low_rules_and_skip_informational_sigma():
    res = {
        "rule_hits": [{"rule_id": "lsadra-auth-off-hours-access", "title": "x", "level": "low",
                       "technique": "T1078", "tactics": ["Persistence"]}],
        "sigma_matches": [
            {"rule_id": "s1", "title": "y", "level": "high", "techniques": ["T1053.003"],
             "tactics": ["Execution"]},
            {"rule_id": "s2", "title": "z", "level": "informational", "techniques": [],
             "tactics": []},
        ],
    }
    sigs = signals_of(res)
    assert [(s["source"], s["base_score"]) for s in sigs] == [("rule", 4.0), ("sigma", 24.0)]
    assert sigs[1]["rule_id"] == "sigma:s1" and sigs[1]["technique_id"] == "T1053.003"


def test_an_unexplained_anomaly_is_a_small_signal():
    [sig] = signals_of({"is_anomaly": True, "severity_label": "HIGH"})
    assert sig["source"] == "anomaly" and sig["base_score"] == risk.ANOMALY_POINTS["HIGH"]
    assert signals_of({"is_anomaly": False}) == []


def test_entities_are_the_host_and_a_real_user():
    assert entities_of({"host": "demo-host-01", "device_id": "d", "effective_username": "bob.demo"}) \
        == [("host", "demo-host-01"), ("user", "bob.demo")]
    assert entities_of({"device_id": "d", "effective_username": "unknown"}) == [("host", "d")]
    # A failed login names the targeted account, not the attacker.
    assert entities_of({"host": "h", "effective_username": "root.demo",
                        "event_type": "auth_failure"}) == [("host", "h")]


def test_benign_corpus_stays_below_the_risk_threshold():
    from lsadra.detection.scorecard import CORPUS_DIR, score_risk

    card = score_risk(CORPUS_DIR)
    benign = card["scenarios"]["benign_background"]
    assert benign["cases"] == [] and benign["max_host_score"] < card["threshold"]
    assert card["scenarios"]["injection_attempts"]["cases"] == []
    for name in ("ssh_bruteforce", "persistence_new_service"):
        assert any(c["entity_type"] == "host" for c in card["scenarios"][name]["cases"]), name


# ── recording and cases ─────────────────────────────────────────────────────

def _result(hours, rule, tactic, level="high", host="demo-host-01", user="bob.demo"):
    return {"event_id": int(hours * 10) + 1, "device_id": "dev-demo", "user_id": "user-demo",
            "host": host, "effective_username": user, "is_anomaly": False,
            "created_at": (T0 + timedelta(hours=hours)).isoformat(),
            "rule_hits": [{"rule_id": rule, "title": rule, "level": level,
                           "technique": "T1110.001", "tactics": [tactic]}]}


def test_record_opens_one_case_per_entity_and_chains_tactics_across_batches(db):
    first = [_result(0, "a", "Credential Access")]
    assert risk.record(first, "shadow") == []
    assert 30 <= first[0]["risk_scores"]["host"] <= 36

    second = [_result(1, "b", "Persistence"), _result(2, "c", "Collection", level="medium")]
    opened = risk.record(second, "shadow")
    assert {(c["entity_type"], c["entity"]) for c in opened} == {
        ("host", "demo-host-01"), ("user", "bob.demo")}
    assert all(c["result_index"] == 1 for c in opened)
    case = db.get_open_risk_notable("host", "demo-host-01")
    assert case["tactics"] == ["Credential Access", "Persistence", "Collection"]
    assert case["mode"] == "shadow" and case["score"] >= 70

    # A later signal updates the open case; it does not open a second one.
    assert risk.record([_result(3, "d", "Exfiltration")], "shadow") == []
    [case] = db.get_risk_notables(status="OPEN", user_id="user-demo")[:1]
    assert db.get_open_risk_notable("host", "demo-host-01")["tactics"][-1] == "Exfiltration"
    assert len(db.get_risk_notables()) == 2  # host + user
    timeline = db.get_risk_events("host", "demo-host-01")
    assert [e["rule_id"] for e in timeline] == ["a", "b", "c", "d"]


def test_alert_mode_turns_the_crossing_event_into_an_alert():
    results = [{"is_anomaly": False, "severity_score": 0.1, "severity_label": "LOW"}]
    case = {"id": 7, "entity_type": "host", "entity": "demo-host-01‮<b>x</b>",
            "result_index": 0, "score": 81.0, "signals": 3, "tactics": ["Persistence"],
            "first_seen": T0.isoformat()}
    risk.raise_case_alerts(results, [case])
    res = results[0]
    assert res["is_anomaly"] is True and res["threat_type"] == risk.RISK_THREAT_TYPE
    assert res["severity_label"] == "HIGH" and res["rule_id"] == "risk:host"
    assert res["risk_cases"] == [7]
    assert "‮" not in res["narrative"] and "<b>" not in res["narrative"]


# ── live path ───────────────────────────────────────────────────────────────

def _off_hours_logins(store, hours):
    for h in hours:
        store.add(h * 60, event_type="auth_success", ip="192.0.2.44")


@pytest.mark.parametrize("mode,alerts", [("shadow", 0), ("alert", 1)])
def test_low_signals_on_a_critical_host_open_a_case(store, orchestrator, monkeypatch, db,
                                                    mode, alerts):
    """Three off-hours logins (low, alone never an alert) on a weight-5 host."""
    monkeypatch.setattr(orch_mod, "risk_mode", lambda: mode)
    db.set_asset_weight("host", "demo-host-01", 5.0)
    for h in (0, 1, 2):
        _off_hours_logins(store, [h])
        _run(orchestrator, monkeypatch)
    case = db.get_open_risk_notable("host", "demo-host-01")
    assert case is not None and case["mode"] == mode
    assert "Persistence" in case["tactics"]
    risk_alerts = [a for a in store.anomalies if a["threat_type"] == risk.RISK_THREAT_TYPE]
    assert len(risk_alerts) == alerts
    assert db.get_open_risk_notable("user", "bob.demo") is None  # weight 1: below threshold


def test_risk_off_records_nothing(store, orchestrator, monkeypatch, db):
    monkeypatch.setattr(orch_mod, "risk_mode", lambda: "off")
    _off_hours_logins(store, [0])
    _run(orchestrator, monkeypatch)
    assert db.get_risk_entities() == []
