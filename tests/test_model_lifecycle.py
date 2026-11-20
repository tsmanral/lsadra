"""
G-18 / G-19 — model training controls.

Training data hygiene, the canary gate, single-flight + cooldown, rollback,
persisted baselines, drift against stored training quantiles, model cards and
the API surface for them. Data is synthetic (demo corpus, RFC 5737 addresses).
"""

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from tests.fixtures import setup_test_db

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "demo" / "corpus"


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    setup_test_db(tmp_path)
    from lsadra import config
    from lsadra.detection import model_lifecycle as lifecycle

    from lsadra.storage.database import create_device, create_user

    create_user("user-a", "owner.demo", "x", "ADMIN")
    create_device("dev-a", "user-a", "demo-host-01", "linux", "x")
    lifecycle.reset_training_gate()
    yield
    lifecycle.reset_training_gate()


def _corpus_events(stem, device_id="dev-a", user_id="user-a", repeat=1, shift_days=0):
    """Demo corpus events as stored rows, newest days ago so they are 'recent'."""
    out = []
    lines = (CORPUS / f"{stem}.jsonl").read_text(encoding="utf-8").splitlines()
    for r in range(repeat):
        for line in lines:
            ev = json.loads(line)
            ts = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
            ts = ts + timedelta(days=shift_days + r)
            out.append(
                {
                    "timestamp": ts.isoformat(),
                    "device_id": device_id,
                    "user_id": user_id,
                    "host": ev.get("host", ""),
                    "effective_username": ev.get("effective_username", ""),
                    "source_ip": ev.get("source_ip") or "",
                    "event_type": ev["event_type"],
                    "raw_message": ev.get("raw_message", ""),
                    "attributes": "{}",
                    "is_synthetic": True,
                }
            )
    return out


def _store_events(events):
    from lsadra.storage.database import insert_events_batch

    insert_events_batch(events)


def _benign_df(repeat=3):
    from lsadra.features.feature_extractor import build_features

    evs = _corpus_events("benign_background", repeat=repeat)
    for i, e in enumerate(evs, 1):
        e["id"] = i
    return build_features(evs)


def _orchestrator():
    from lsadra import config
    from lsadra.detection.detection_orchestrator import DetectionOrchestrator

    return DetectionOrchestrator(model_dir=config.MODEL_DIR)


# ── hygiene ───────────────────────────────────────────────────────────────


def test_labelled_attack_reads_ground_truth():
    from lsadra.detection.model_lifecycle import labelled_attack

    def ev(attrs):
        return {"attributes": attrs}

    assert labelled_attack(ev({"ground_truth": {"label": "malicious"}}))
    assert labelled_attack(ev(json.dumps({"ground_truth": {"label": "suspicious"}})))
    assert not labelled_attack(ev({"ground_truth": {"label": "benign"}}))
    assert not labelled_attack(ev({"source_type": "syslog"}))
    assert not labelled_attack(ev("{not json"))
    assert not labelled_attack({})


def test_seeded_demo_corpus_trains_a_model():
    """Regression: a fresh install seeded with the whole demo corpus got no model.

    The corpus's own attack events were learned as normal, so the candidate
    missed the canary scenarios and every automatic run was rejected.
    """
    rows = []
    for f in sorted(CORPUS.glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            ev = json.loads(line)
            rows.append(
                {
                    "timestamp": ev["timestamp"],
                    "device_id": "dev-a",
                    "user_id": "user-a",
                    "host": ev.get("host", ""),
                    "effective_username": ev.get("effective_username", ""),
                    "source_ip": ev.get("source_ip") or "",
                    "event_type": ev["event_type"],
                    "raw_message": ev.get("raw_message", ""),
                    "attributes": ev.get("attributes", {}),
                    "is_synthetic": True,
                }
            )
    rows.sort(key=lambda r: r["timestamp"])
    _store_events(rows)

    result = _orchestrator().retrain(trigger="auto")

    attacks = sum(1 for r in rows if r["attributes"]["ground_truth"]["label"] != "benign")
    assert result["selection"]["excluded_labelled_attacks"] == attacks
    assert result["status"] == "promoted", result.get("canary")


def test_cap_device_share_limits_dominant_device():
    from lsadra.detection.model_lifecycle import cap_device_share

    events = [{"id": i, "device_id": "big"} for i in range(900)]
    events += [{"id": 1000 + i, "device_id": "small"} for i in range(100)]
    kept, dropped = cap_device_share(events, 0.5)
    counts = pd.Series([e["device_id"] for e in kept]).value_counts()
    assert counts["big"] <= 0.5 * len(kept)
    assert counts["small"] == 100
    assert dropped == 1000 - len(kept)
    # the newest events of the capped device are the ones kept
    assert max(e["id"] for e in kept if e["device_id"] == "big") == 899


def test_cap_device_share_noop_for_single_device():
    from lsadra.detection.model_lifecycle import cap_device_share

    events = [{"id": i, "device_id": "only"} for i in range(50)]
    assert cap_device_share(events, 0.5) == (events, 0)


def test_training_selection_drops_anomalies_and_open_incidents():
    from lsadra.detection.model_lifecycle import select_training_events
    from lsadra.storage.database import (
        create_incident,
        get_connection,
        insert_anomaly,
    )

    base = datetime(2026, 1, 15, 2, 0, tzinfo=timezone.utc)
    rows = []
    for i in range(30):
        rows.append(
            {
                "timestamp": (base + timedelta(minutes=i)).isoformat(),
                "device_id": "dev-a",
                "user_id": "user-a",
                "host": "demo-host-01",
                "effective_username": "alice.demo",
                "source_ip": "198.51.100.7" if 10 <= i < 15 else "192.0.2.45",
                "event_type": "auth_success",
                "raw_message": "synthetic",
                "attributes": "{}",
            }
        )
    _store_events(rows)
    conn = get_connection()
    ids = [r[0] for r in conn.execute("SELECT id FROM normalized_events ORDER BY id")]
    conn.close()

    # event #3 is an anomaly; events 10-14 sit inside an open incident window
    insert_anomaly(
        {
            "event_id": ids[3],
            "device_id": "dev-a",
            "is_anomaly": True,
            "severity_score": 0.5,
            "severity_label": "MEDIUM",
        }
    )
    inc = create_incident(
        "dev-a", "198.51.100.7", "Brute Force", "HIGH", (base + timedelta(minutes=10)).isoformat()
    )
    conn = get_connection()
    conn.execute(
        "UPDATE incidents SET last_seen = ? WHERE id = ?",
        ((base + timedelta(minutes=14)).isoformat(), inc),
    )
    conn.commit()
    conn.close()

    events, stats = select_training_events()
    kept_ids = {e["id"] for e in events}
    assert ids[3] not in kept_ids
    assert not kept_ids & set(ids[10:15])
    assert stats["excluded_anomalies"] == 1
    assert stats["excluded_open_incidents"] == 5
    assert stats["event_count"] == 24

    # once the incident is resolved its events are usable again
    conn = get_connection()
    conn.execute("UPDATE incidents SET status = 'RESOLVED' WHERE id = ?", (inc,))
    conn.commit()
    conn.close()
    events, stats = select_training_events()
    assert stats["event_count"] == 29


# ── canary gate ───────────────────────────────────────────────────────────


def test_canary_passes_clean_candidate_and_promotes():
    from lsadra.detection import model_lifecycle as lifecycle
    from lsadra.storage.database import get_training_runs

    orch = _orchestrator()
    result = orch.train(_benign_df(), trigger="other")

    assert result["status"] == "promoted", result["canary"]
    assert result["canary"]["passed"]
    assert orch._trained
    store = lifecycle.current_store(orch.model_dir)
    for name in (lifecycle.ENSEMBLE_FILE, lifecycle.BASELINE_FILE, lifecycle.REFERENCE_FILE):
        assert store.sha256(name), name
    assert get_training_runs()[0]["status"] == "promoted"


def test_canary_rejects_poisoned_candidate_and_keeps_live_models():
    """Training data full of brute-force traffic teaches the models that brute force
    is normal; the canary must catch that and keep the current models."""
    from lsadra.detection import model_lifecycle as lifecycle
    from lsadra.features.feature_extractor import build_features
    from lsadra.storage.database import get_training_runs

    orch = _orchestrator()
    assert orch.train(_benign_df(), trigger="other")["status"] == "promoted"
    store = lifecycle.current_store(orch.model_dir)
    live_hash = store.sha256(lifecycle.ENSEMBLE_FILE)
    live_ensemble = orch.ensemble

    poisoned = _corpus_events("benign_background") + _corpus_events("ssh_bruteforce", repeat=3)
    for i, e in enumerate(poisoned, 1):
        e["id"] = i
    result = orch.train(build_features(poisoned), trigger="other")

    assert result["status"] == "rejected"
    assert not result["canary"]["scenarios"]["ssh_bruteforce"]["passed"]
    assert orch.ensemble is live_ensemble
    assert store.sha256(lifecycle.ENSEMBLE_FILE) == live_hash
    assert get_training_runs()[0]["status"] == "rejected"


def test_canary_fails_closed_without_scenarios(monkeypatch):
    from lsadra.detection.model_lifecycle import run_canary

    res = run_canary(None, None, scenarios=["no_such_scenario"], min_recall=0.5)
    assert res["passed"] is False


def test_canary_corpus_ships_in_the_package():
    """An installed or bundled server has no demo/ folder: the canary reads the
    copies inside the package, which must match the labelled demo corpus."""
    from lsadra import config
    from lsadra.detection import model_lifecycle as lifecycle

    package = Path(lifecycle.__file__).resolve().parent
    assert lifecycle.CANARY_DIR.parent == package
    shipped = {p.name: p.read_bytes() for p in lifecycle.CANARY_DIR.glob("*.jsonl")}
    source = {p.name: p.read_bytes() for p in CORPUS.glob("*.jsonl")}
    assert shipped == source, "update lsadra/detection/canary/ with demo/corpus/"
    for scenario in config.CANARY_SCENARIOS:
        assert f"{scenario}.jsonl" in shipped


# ── single flight + cooldown ──────────────────────────────────────────────


def test_training_gate_is_single_flight_and_has_cooldown(monkeypatch):
    from lsadra import config
    from lsadra.detection import model_lifecycle as lifecycle

    monkeypatch.setattr(config, "RETRAIN_COOLDOWN_SECONDS", 600.0)
    entered = threading.Event()
    release = threading.Event()

    def hold():
        with lifecycle.training_gate():
            entered.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    assert entered.wait(5)
    with pytest.raises(lifecycle.TrainingRefused) as busy:
        with lifecycle.training_gate():
            pass
    assert busy.value.status_code == 409
    release.set()
    t.join()

    with pytest.raises(lifecycle.TrainingRefused) as cool:
        with lifecycle.training_gate():
            pass
    assert cool.value.status_code == 429
    assert cool.value.retry_after and cool.value.retry_after > 0
    # rollback is not subject to the cooldown
    with lifecycle.training_gate(enforce_cooldown=False):
        pass


def test_retrain_from_database_applies_controls_and_audits(monkeypatch):
    from lsadra import config
    from lsadra.detection import model_lifecycle as lifecycle
    from lsadra.storage.database import get_training_runs

    monkeypatch.setattr(config, "MIN_TRAINING_EVENTS", 50)
    _store_events(_corpus_events("benign_background", repeat=3))
    orch = _orchestrator()

    result = orch.retrain(trigger="admin", requested_by="admin-1")
    assert result["status"] == "promoted", result
    run = get_training_runs()[0]
    assert run["trigger"] == "admin" and run["requested_by"] == "admin-1"
    assert run["event_count"] == result["selection"]["event_count"] > 0

    with pytest.raises(lifecycle.TrainingRefused):
        orch.retrain(trigger="admin", requested_by="admin-1")
    assert get_training_runs()[0]["status"] == "refused"


def test_retrain_skips_with_too_few_events(monkeypatch):
    from lsadra import config
    from lsadra.detection import model_lifecycle as lifecycle

    monkeypatch.setattr(config, "MIN_TRAINING_EVENTS", 10_000)
    _store_events(_corpus_events("benign_background"))
    result = _orchestrator().retrain(trigger="api", requested_by="admin-1")
    assert result["status"] == "skipped"
    # monotonic() + 30 - monotonic() can round a hair above 30 on a long-running clock
    remaining = lifecycle.cooldown_remaining()
    assert 0 < remaining <= lifecycle.SKIPPED_RUN_COOLDOWN_SECONDS + 1e-6


# ── rollback ──────────────────────────────────────────────────────────────


def test_rollback_restores_previous_models_and_can_be_undone():
    from lsadra.detection import model_lifecycle as lifecycle

    orch = _orchestrator()
    assert orch.train(_benign_df(repeat=2), trigger="other")["status"] == "promoted"
    store = lifecycle.current_store(orch.model_dir)
    first = store.sha256(lifecycle.ENSEMBLE_FILE)
    assert orch.train(_benign_df(repeat=3), trigger="other")["status"] == "promoted"
    second = store.sha256(lifecycle.ENSEMBLE_FILE)
    assert first != second

    assert orch.rollback(requested_by="admin-1")["status"] == "rolled_back"
    assert store.sha256(lifecycle.ENSEMBLE_FILE) == first
    assert orch._trained

    orch.rollback(requested_by="admin-1")
    assert store.sha256(lifecycle.ENSEMBLE_FILE) == second


def test_rollback_without_previous_is_refused():
    from lsadra.detection import model_lifecycle as lifecycle

    with pytest.raises(lifecycle.TrainingRefused) as exc:
        _orchestrator().rollback()
    assert exc.value.status_code == 404


def test_other_orchestrators_reload_after_promotion():
    a = _orchestrator()
    b = _orchestrator()
    assert not b._trained
    a.train(_benign_df(), trigger="other")
    b._reload_if_swapped()
    assert b._trained


# ── G-19: baselines, drift, cards ─────────────────────────────────────────


def test_baselines_survive_restart():
    orch = _orchestrator()
    orch.train(_benign_df(), trigger="other")
    entities = orch.baseline.coverage()["entities"]
    assert entities > 0

    fresh = _orchestrator()
    assert fresh.baseline.coverage()["entities"] == entities
    df = _benign_df(repeat=1)
    assert fresh.baseline.score(df) == orch.baseline.score(df)


def test_tampered_baseline_is_not_loaded():
    from lsadra.detection import model_lifecycle as lifecycle

    orch = _orchestrator()
    orch.train(_benign_df(), trigger="other")
    path = orch.model_dir / lifecycle.BASELINE_FILE
    data = json.loads(path.read_text())
    data["sigma"] = 1e9  # would silence the layer
    path.write_text(json.dumps(data))
    assert _orchestrator().baseline.coverage()["entities"] == 0


def test_model_cards_describe_each_model():
    from lsadra.detection import model_lifecycle as lifecycle

    orch = _orchestrator()
    orch.train(_benign_df(), trigger="other")
    cards = lifecycle.read_cards(orch.model_dir)
    store = lifecycle.current_store(orch.model_dir)
    for name in ("ensemble", "baseline"):
        card = cards[name]
        assert card["sha256"] == store.sha256(card["file"])
        assert card["features"]
        assert card["canary"]["passed"]
        assert card["training_data"]["event_count"] > 0
        assert card["training_data"]["window_start"]
        assert "lsadra" in card["library_versions"]
        assert card["version"] >= 1


def test_psi_against_reference_counts_out_of_range_values():
    from lsadra.detection.model_lifecycle import psi_against_reference, reference_quantiles

    rng = np.random.default_rng(0)
    ref = reference_quantiles(pd.DataFrame({"failures_15m": rng.normal(0, 1, 2000)}))
    feat = ref["features"]["failures_15m"]
    assert psi_against_reference(feat, rng.normal(0, 1, 2000)) < 0.1
    # every value above the training maximum must still count as drift
    assert psi_against_reference(feat, np.full(500, 1000.0)) > 1.0


def test_scheduled_drift_uses_stored_reference(monkeypatch):
    from lsadra.detection import drift_detector
    from lsadra.storage.database import get_drift_records, get_latest_model

    orch = _orchestrator()
    orch.train(_benign_df(), trigger="other")

    # no events in the window yet: nothing to measure
    assert drift_detector.run() == {}

    now = datetime.now(timezone.utc)
    burst = []
    for i in range(200):
        burst.append(
            {
                "timestamp": (now - timedelta(minutes=200 - i) / 4).isoformat(),
                "device_id": "dev-a",
                "user_id": "user-a",
                "host": "demo-host-01",
                "effective_username": f"user{i % 40}.demo",
                "source_ip": "203.0.113.9",
                "event_type": "auth_failure",
                "raw_message": "synthetic",
                "attributes": "{}",
            }
        )
    _store_events(burst)

    drifted = drift_detector.run()
    assert drifted, "a brute-force burst must drift from benign training data"
    assert get_drift_records("ensemble")
    assert get_latest_model("ensemble")["is_stale"]


def test_scheduled_drift_without_reference_is_a_noop():
    from lsadra.detection import drift_detector

    assert drift_detector.run() == {}


# ── API ───────────────────────────────────────────────────────────────────


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from server import app

    return TestClient(app)


def _token(role):
    from lsadra.auth import create_access_token, hash_password
    from lsadra.storage.database import create_user

    uid = f"{role.lower()}-1"
    create_user(uid, f"{role.lower()}.demo", hash_password("pass-demo"), role)
    return {"Authorization": f"Bearer {create_access_token(uid, f'{role.lower()}.demo', role)}"}


def test_dashboard_retrain_is_admin_only(client):
    assert client.post("/api/dashboard/retrain", headers=_token("ANALYST")).status_code == 403


def test_retrain_routes_share_the_cooldown(client, monkeypatch):
    from lsadra import config

    monkeypatch.setattr(config, "MIN_TRAINING_EVENTS", 50)
    _store_events(_corpus_events("benign_background", repeat=3))
    admin = _token("ADMIN")

    first = client.post("/api/dashboard/retrain", headers=admin)
    assert first.status_code == 200 and first.json()["status"] == "promoted"
    again = client.post("/api/dashboard/retrain", headers=admin)
    assert again.status_code == 429 and "retry-after" in again.headers
    assert client.post("/admin/retrain", headers=admin).status_code == 429


def test_model_status_and_rollback_endpoints(client):
    admin = _token("ADMIN")
    analyst = _token("ANALYST")
    viewer = _token("VIEWER")

    assert client.get("/api/models/status", headers=viewer).status_code == 403
    assert client.post("/api/models/rollback", headers=analyst).status_code == 403
    assert client.post("/api/models/rollback", headers=admin).status_code == 404

    from lsadra.ingestion.api_ingestion import _get_orchestrator

    orch = _get_orchestrator()
    orch.train(_benign_df(repeat=2), trigger="other")
    orch.train(_benign_df(repeat=3), trigger="other")

    status = client.get("/api/models/status", headers=analyst).json()
    assert status["trained"] is True
    assert status["baseline_coverage"]["entities"] > 0
    assert status["model_cards"]["ensemble"]["sha256"]
    assert status["previous_available"] is True
    assert status["training_runs"] and "requested_by" not in status["training_runs"][0]

    r = client.post("/api/models/rollback", headers=admin)
    assert r.status_code == 200 and r.json()["status"] == "rolled_back"
