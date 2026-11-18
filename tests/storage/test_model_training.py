"""Contract: model training audit trail and training-data selection (G-18 / G-19).

insert_training_run, finish_training_run, get_training_runs,
get_training_events, get_open_incident_windows, get_recent_events.
"""

from tests.storage._support import DEVICE_ID, make_event

RUN_KEYS = {
    "id", "started_at", "finished_at", "trigger", "requested_by", "status",
    "event_count", "device_count", "excluded_count", "canary", "detail",
}


def test_insert_finish_and_list_training_runs(db):
    first = db.insert_training_run("auto", None, "promoted", event_count=10, device_count=1,
                                   canary={"passed": True})
    second = db.insert_training_run("api", "user-1", "running", finished=False)
    assert second > first

    runs = db.get_training_runs()
    assert [r["id"] for r in runs] == [second, first]  # newest first
    assert all(set(r) == RUN_KEYS for r in runs)
    assert runs[0]["finished_at"] is None
    assert runs[1]["canary"] == {"passed": True}

    db.finish_training_run(second, "rejected", event_count=5, excluded_count=2,
                           canary={"passed": False}, detail="canary")
    run = db.get_training_runs(limit=1)[0]
    assert run["status"] == "rejected" and run["finished_at"]
    assert run["excluded_count"] == 2 and run["canary"] == {"passed": False}


def test_training_events_exclude_anomalies(seeded):
    seeded.insert_events_batch([make_event(timestamp=f"2026-01-01T00:00:0{i}") for i in range(5)])
    ids = [e["id"] for e in seeded.get_recent_events(10)]
    assert ids == sorted(ids, reverse=True)  # newest first
    seeded.insert_anomaly({"event_id": ids[0], "device_id": DEVICE_ID, "is_anomaly": True})
    seeded.insert_anomaly({"event_id": ids[1], "device_id": DEVICE_ID, "is_anomaly": False})

    events, excluded = seeded.get_training_events(10)
    assert excluded == 1
    assert [e["id"] for e in events] == sorted(ids[1:])  # oldest first, flagged one gone
    events, excluded = seeded.get_training_events(2)  # only the newest two are considered
    assert [e["id"] for e in events] == [ids[1]] and excluded == 1


def test_open_incident_windows(seeded):
    open_id = seeded.create_incident(DEVICE_ID, "192.0.2.10", "Brute Force", "HIGH",
                                     "2026-01-01T00:00:00")
    closed = seeded.create_incident(DEVICE_ID, "192.0.2.11", "Brute Force", "HIGH",
                                    "2026-01-01T00:00:00")
    seeded.update_incident_status(closed, "RESOLVED")
    windows = seeded.get_open_incident_windows()
    assert windows == [{
        "device_id": DEVICE_ID, "source_ip": "192.0.2.10",
        "first_seen": "2026-01-01T00:00:00", "last_seen": "2026-01-01T00:00:00",
    }]
    assert open_id


def test_proposed_actions_are_only_proposed_until_a_human_decides(seeded):
    inc = seeded.create_incident(DEVICE_ID, "192.0.2.10", "Brute Force", "HIGH",
                                 "2026-01-01T00:00:00")
    pid = seeded.insert_proposed_action(inc, "block_source_ip", "192.0.2.10", "burst",
                                        evidence_event_ids=[1, 2])
    other = seeded.insert_proposed_action(inc, "escalate", DEVICE_ID)

    pending = seeded.get_proposed_actions(incident_id=inc, status="PROPOSED")
    assert [p["id"] for p in pending] == [other, pid]
    assert pending[1]["evidence_event_ids"] == [1, 2]
    assert pending[0]["evidence_event_ids"] == []

    assert seeded.decide_proposed_action(pid, "APPROVED", "user-1") is True
    assert seeded.decide_proposed_action(pid, "REJECTED", "user-1") is False  # already decided
    approved = seeded.get_proposed_actions(status="APPROVED")
    assert len(approved) == 1 and approved[0]["decided_by"] == "user-1"
    assert seeded.get_proposed_actions(incident_id=inc + 99) == []
    import pytest

    with pytest.raises(ValueError):
        seeded.decide_proposed_action(other, "EXECUTE", "user-1")
