"""
Growth retraining (ADR 0007 follow-up to G-18).

The first automatic model is fitted on the first MIN_TRAINING_EVENTS usable
events. While the live models saw fewer than TRAINING_MAX_EVENTS, a new run
starts each time the stored event count has grown by AUTO_RETRAIN_GROWTH since
the last run, through ``retrain`` so every training control applies. Data is
synthetic (demo corpus, RFC 5737 addresses).
"""

import pytest

from tests.test_model_lifecycle import _corpus_events, _db, _orchestrator, _store_events  # noqa: F401


@pytest.fixture
def no_cooldown(monkeypatch):
    from lsadra import config

    monkeypatch.setattr(config, "RETRAIN_COOLDOWN_SECONDS", 0.0)
    monkeypatch.setattr(config, "AUTO_RETRAIN_GROWTH", 2.0)


def _first_model():
    """Store the benign corpus (64 events) and train the first model from the database."""
    _store_events(_corpus_events("benign_background"))
    orch = _orchestrator()
    assert orch.retrain(trigger="auto")["status"] == "promoted"
    return orch


def _spy(orch, monkeypatch):
    calls = []
    real = orch.retrain

    def spy(trigger="api", requested_by=None):
        calls.append(trigger)
        return real(trigger=trigger, requested_by=requested_by)

    monkeypatch.setattr(orch, "retrain", spy)
    return calls


def test_due_only_after_growth_and_below_the_cap(monkeypatch):
    from lsadra import config
    from lsadra.detection.detection_orchestrator import growth_retrain_due

    monkeypatch.setattr(config, "AUTO_RETRAIN_GROWTH", 2.0)
    monkeypatch.setattr(config, "TRAINING_MAX_EVENTS", 10_000)
    assert not growth_retrain_due(99, base=50, trained_on=50)
    assert growth_retrain_due(100, base=50, trained_on=50)
    assert not growth_retrain_due(100_000, base=50, trained_on=10_000)  # already at the cap
    assert not growth_retrain_due(100, base=None, trained_on=None)      # no model yet
    monkeypatch.setattr(config, "AUTO_RETRAIN_GROWTH", 0.0)
    assert not growth_retrain_due(100_000, base=50, trained_on=50)      # turned off


def test_one_retrain_per_doubling(no_cooldown, monkeypatch):
    orch = _first_model()
    assert orch._trained_on == 64 and orch._growth_base == 64
    calls = _spy(orch, monkeypatch)

    orch._maybe_growth_retrain(127)
    assert calls == []

    _store_events(_corpus_events("benign_background", shift_days=1))
    orch._maybe_growth_retrain(128)
    assert calls == ["auto-growth"]
    assert orch._trained_on == 128

    for clock in (129, 200, 255):
        orch._maybe_growth_retrain(clock)
    assert calls == ["auto-growth"]
    orch._maybe_growth_retrain(256)
    assert calls == ["auto-growth", "auto-growth"]


def test_a_rejected_candidate_waits_for_the_next_doubling(no_cooldown, monkeypatch):
    from lsadra.detection import model_lifecycle as lifecycle

    orch = _first_model()
    monkeypatch.setattr(lifecycle, "run_canary",
                        lambda *a, **k: {"passed": False, "scenarios": {}})
    calls = _spy(orch, monkeypatch)

    orch._maybe_growth_retrain(128)
    assert calls == ["auto-growth"]
    assert orch._trained_on == 64  # live models unchanged
    for clock in range(129, 256, 7):
        orch._maybe_growth_retrain(clock)
    assert calls == ["auto-growth"]  # not retried every cooldown
    orch._maybe_growth_retrain(256)
    assert calls == ["auto-growth", "auto-growth"]


def test_growth_runs_are_audited_like_other_runs(no_cooldown):
    from lsadra.detection import model_lifecycle as lifecycle
    from lsadra.storage.database import get_training_runs

    orch = _first_model()
    _store_events(_corpus_events("benign_background", shift_days=1))
    orch._maybe_growth_retrain(128)
    assert get_training_runs(5)[0]["trigger"] == "auto-growth"
    card = lifecycle.read_cards(orch.model_dir)["ensemble"]
    assert card["trigger"] == "auto-growth"
    assert card["training_data"]["event_count"] == 128


def test_restart_picks_up_the_training_size_from_the_model_card(no_cooldown):
    _first_model()
    fresh = _orchestrator()
    assert fresh._trained_on == 64
    assert fresh._growth_base == 64


def test_respects_a_running_cooldown(monkeypatch):
    from lsadra import config

    orch = _first_model()  # default 600 s cooldown now running
    monkeypatch.setattr(config, "AUTO_RETRAIN_GROWTH", 2.0)
    calls = _spy(orch, monkeypatch)
    orch._maybe_growth_retrain(10_000)
    assert calls == []
    assert orch._growth_base == 64  # still due once the cooldown ends


def test_online_batches_drive_the_check(no_cooldown, monkeypatch):
    orch = _first_model()
    seen = []
    monkeypatch.setattr(orch, "_maybe_growth_retrain", seen.append)
    evs = _corpus_events("benign_background", shift_days=2)[:5]
    _store_events(evs)
    from lsadra.storage.database import get_connection

    with get_connection() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM normalized_events ORDER BY id DESC LIMIT 5").fetchall()]
    monkeypatch.setattr("lsadra.detection.detection_orchestrator.MIN_BASELINE_EVENTS", 0)
    orch._process_new_events("dev-a", sorted(rows, key=lambda r: r["id"]))
    assert seen == [max(r["id"] for r in rows)]
