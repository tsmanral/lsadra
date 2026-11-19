"""
LSADRA security regression — online detection must keep running on messy input.

Attacker story: a sender controls the content of the events it submits. If one
batch of events makes the detection run raise, the device's watermark never
moves, every later run fetches the same batch and fails again, and detection
for that device is silently off from then on.

These tests pin two things:

1. Event timestamps written in different (valid or invalid) styles within one
   batch are all parsed, and every event is still scored.
2. Even if some future input does make a run fail, the orchestrator gives up on
   that batch after ``MAX_BATCH_FAILURES`` attempts and detection resumes.

All values are synthetic (*.demo users, RFC 5737 addresses).
"""

import pandas as pd
import pytest

import lsadra.detection.detection_orchestrator as orch_mod
from lsadra.features.feature_extractor import build_features
from lsadra.features.timestamps import parse_event_timestamps

DEVICE = "device-resilience.demo"

MIXED_TIMESTAMPS = [
    "2026-03-02T10:00:00",
    "2026-03-02T10:00:01.250000",
    "2026-03-02T10:00:02+00:00",
    "2026-03-02T10:00:03.5Z",
    "2026-03-02 10:00:04",
    "2026-03-02T12:00:05+02:00",
    "not-a-timestamp",
    "",
    None,
    "2026-03-02T10:00:09",
]


def _events(timestamps, start_id=1):
    return [
        {
            "id": start_id + i,
            "timestamp": ts,
            "device_id": DEVICE,
            "user_id": "user-1",
            "effective_username": "alice.demo",
            "source_ip": "192.0.2.10",
            "event_type": "ssh_failed_password" if i % 2 else "ssh_accepted_password",
            "raw_message": "synthetic",
            "is_synthetic": True,
        }
        for i, ts in enumerate(timestamps)
    ]


def test_parse_event_timestamps_handles_every_style():
    parsed = parse_event_timestamps(pd.Series(MIXED_TIMESTAMPS, dtype=object))
    assert len(parsed) == len(MIXED_TIMESTAMPS)
    assert not parsed.isna().any()
    assert parsed.dt.tz is None
    # Offsets are normalised to UTC.
    assert parsed.iloc[2] == pd.Timestamp("2026-03-02T10:00:02")
    assert parsed.iloc[5] == pd.Timestamp("2026-03-02T10:00:05")
    assert parsed.iloc[1] == pd.Timestamp("2026-03-02T10:00:01.25")


def test_parse_event_timestamps_all_invalid_still_fills():
    parsed = parse_event_timestamps(pd.Series(["garbage", None, ""], dtype=object))
    assert not parsed.isna().any()


@pytest.mark.parametrize(
    "timestamps",
    [
        MIXED_TIMESTAMPS,
        ["2026-03-02T10:00:00", "2026-03-02T10:00:01.123456"] * 5,
        ["2026-03-02T10:00:00+00:00", "2026-03-02T10:00:01"] * 5,
        ["garbage"] * 4,
    ],
)
def test_build_features_scores_every_event(timestamps):
    df = build_features(_events(timestamps))
    assert len(df) == len(timestamps)
    assert not df["timestamp"].isna().any()


@pytest.fixture
def fake_store(monkeypatch):
    """Replace the orchestrator's database calls with an in-memory store."""
    store = {"events": [], "watermark": 0, "anomalies": 0}

    monkeypatch.setattr(orch_mod, "DETECTION_THROTTLE_SECONDS", 0)
    monkeypatch.setattr(orch_mod, "MIN_BASELINE_EVENTS", 1)
    monkeypatch.setattr(orch_mod, "get_watermark", lambda d: store["watermark"])
    monkeypatch.setattr(
        orch_mod,
        "get_events_since",
        lambda d, after_id: [e for e in store["events"] if e["id"] > after_id],
    )
    monkeypatch.setattr(
        orch_mod, "set_watermark", lambda d, wm: store.__setitem__("watermark", wm)
    )
    monkeypatch.setattr(
        orch_mod, "increment_device_event_count", lambda d, n: len(store["events"])
    )
    monkeypatch.setattr(orch_mod, "get_device", lambda d: {"id": d, "status": "ONLINE"})
    monkeypatch.setattr(orch_mod, "update_device_status", lambda d, s: None)

    def _insert(res):
        store["anomalies"] += 1
        return store["anomalies"]

    monkeypatch.setattr(orch_mod, "insert_anomaly", _insert)
    return store


@pytest.fixture
def orchestrator(monkeypatch):
    o = orch_mod.DetectionOrchestrator()
    o._trained = False  # untrained models: layers degrade gracefully
    monkeypatch.setattr(o, "_auto_train", lambda d: None)
    monkeypatch.setattr(o.incident_manager, "process_anomaly", lambda res: None)
    monkeypatch.setattr(orch_mod.alert_hub, "publish", lambda res: None)
    return o


def test_mixed_timestamp_batch_advances_watermark(fake_store, orchestrator):
    fake_store["events"] = _events(MIXED_TIMESTAMPS)
    orchestrator.run_for_new_events(DEVICE)
    assert fake_store["watermark"] == len(MIXED_TIMESTAMPS)

    # The next batch is processed normally.
    fake_store["events"] += _events(["2026-03-02T10:01:00"] * 3, start_id=100)
    orchestrator.run_for_new_events(DEVICE)
    assert fake_store["watermark"] == 102


def test_failing_batch_is_skipped_after_retries(fake_store, orchestrator, monkeypatch):
    fake_store["events"] = _events(["2026-03-02T10:00:00"] * 5)
    real_build_features = orch_mod.build_features

    def _boom(events):
        raise ValueError("synthetic failure")

    monkeypatch.setattr(orch_mod, "build_features", _boom)

    for attempt in range(1, orch_mod.MAX_BATCH_FAILURES + 1):
        with pytest.raises(ValueError):
            orchestrator.run_for_new_events(DEVICE)
        if attempt < orch_mod.MAX_BATCH_FAILURES:
            assert fake_store["watermark"] == 0

    # Detection moved past the poisoned batch instead of retrying it forever.
    assert fake_store["watermark"] == 5

    # And later events are scored again once input is healthy.
    monkeypatch.setattr(orch_mod, "build_features", real_build_features)
    fake_store["events"] += _events(["2026-03-02T10:01:00"] * 2, start_id=50)
    orchestrator.run_for_new_events(DEVICE)
    assert fake_store["watermark"] == 51
