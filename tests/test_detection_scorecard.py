"""
Release gate: the rules scorecard on the labelled demo corpus (audit G-5, G-12, G-14).

- The benign control set raises no rule alert.
- Every attack scenario raises at least one alert on an attack event.
- Every rule that names a corpus scenario fires on an attack event in it.
- docs/detection/scorecard.json matches the current rules and corpus, so a rule
  change cannot land without its new numbers.
"""

import json
from pathlib import Path

import pytest

from lsadra.detection.rule_engine import RULES
from lsadra.detection.scorecard import (
    ATTACK_LABELS,
    CORPUS_DIR,
    _load,
    build_scorecard,
    render_markdown,
    score_scenario,
)

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs" / "detection"


@pytest.fixture(scope="module")
def card():
    return build_scorecard()


def test_benign_corpus_raises_no_rule_alert(card):
    benign = card["scenarios"]["benign_background"]
    assert benign["events"] == 64
    assert benign["benign_events_alerted"] == 0


def test_no_benign_event_alerts_in_any_scenario(card):
    assert card["summary"]["benign_events_alerted"] == 0


@pytest.mark.parametrize(
    "scenario", ["ssh_bruteforce", "persistence_new_service", "data_movement_offhours"]
)
def test_every_attack_scenario_is_detected(card, scenario):
    assert card["scenarios"][scenario]["detected"]


@pytest.mark.parametrize("rule_id", sorted(r.id for r in RULES.values() if r.scenario))
def test_rule_fires_in_its_corpus_scenario(rule_id):
    scenario = RULES[rule_id].scenario
    results = score_scenario(_load(CORPUS_DIR / f"{scenario}.jsonl"))
    hits = [r for r in results if rule_id in r["matches"] and r["label"] in ATTACK_LABELS]
    assert hits, f"{rule_id} never fires on an attack event in {scenario}"


def test_injection_corpus_strings_do_not_trigger_rules(card):
    """Look-alike event types (zero-width, bidi, markup) are not real events."""
    assert card["scenarios"]["injection_attempts"]["attack_events_alerted"] == 0


def test_committed_scorecard_is_current(card):
    committed = json.loads((DOCS / "scorecard.json").read_text(encoding="utf-8"))
    assert committed == json.loads(json.dumps(card)), (
        "docs/detection/scorecard.json is stale: run python scripts/detection_scorecard.py"
    )
    assert (DOCS / "scorecard.md").read_text(encoding="utf-8") == render_markdown(card)
