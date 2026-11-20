"""
Contract: every ATT&CK technique LSADRA names is valid in the pinned release (audit G-13).

The pinned table (lsadra/detection/data/attack-enterprise.json) is generated
from MITRE's STIX data by scripts/update_attack_data.py. These tests fail when a
rule, a narrative, any technique ID written in the product code, or a demo
corpus label is unknown, revoked or deprecated in that release.
"""

import json
import re
from pathlib import Path

import pytest

from lsadra.detection import attack_map
from lsadra.detection.attack_map import ATTACK_VERSION, get_technique, is_valid, technique
from lsadra.detection.rule_engine import RULES

REPO = Path(__file__).resolve().parent.parent
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def test_table_is_the_pinned_release():
    data = json.loads(
        (REPO / "lsadra" / "detection" / "data" / "attack-enterprise.json").read_text("utf-8")
    )
    assert data["attack_version"] == ATTACK_VERSION
    assert ATTACK_VERSION.split(".")[0] == "20"
    assert len(data["techniques"]) > 600 and len(data["tactics"]) >= 14


def test_tactics_include_v19_split():
    """v19 split Defense Evasion into Stealth and Defense Impairment."""
    names = {t.name for t in attack_map.tactics().values()}
    assert {"Stealth", "Defense Impairment", "Credential Access"} <= names
    assert "Defense Evasion" not in names


def test_lookup_and_tactics():
    t = technique("T1110.001")
    assert t.name == "Password Guessing"
    assert [x.name for x in t.tactics] == ["Credential Access"]
    assert t.url == "https://attack.mitre.org/techniques/T1110/001/"


def test_revoked_and_unknown_ids_are_rejected():
    assert get_technique("T1070.001").revoked  # moved to T1685.005 in v20
    with pytest.raises(KeyError, match="T1685.005"):
        technique("T1070.001")
    with pytest.raises(KeyError):
        technique("T9999")
    assert not is_valid("T9999") and not is_valid("") and not is_valid("N/A")


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_every_rule_technique_is_active_with_tactics(rule_id):
    for tid in RULES[rule_id].technique_ids:
        tech = technique(tid)
        assert tech.tactics, f"{rule_id}: {tid} has no tactic"


def test_corrected_mappings():
    """Mappings the audit found wrong now point at the specific technique."""
    by_event = {}
    for r in RULES.values():
        for et in r.event_types:
            by_event.setdefault(et, set()).update(r.technique_ids)
    assert "T1053.003" in by_event["cron_modified"]  # not T1547
    assert "T1543.002" in by_event["service_install"]  # systemd, not T1547
    assert "T1543.003" in by_event["service_install"]  # Windows service
    assert "T1053.005" in by_event["scheduled_task_create"]  # not T1547
    all_ids = {t for r in RULES.values() for t in r.technique_ids}
    assert "T1068" not in all_ids  # sudo is not exploitation for privilege escalation
    assert "T1190" not in all_ids  # no rule guesses T1190 any more


def _code_files():
    for path in (REPO / "lsadra").rglob("*.py"):
        yield path
    for path in (REPO / "frontend" / "src").rglob("*.ts*"):
        yield path


def test_every_technique_id_in_product_code_is_valid():
    bad = []
    for path in _code_files():
        for tid in set(TECHNIQUE_RE.findall(path.read_text(encoding="utf-8", errors="ignore"))):
            if not is_valid(tid):
                bad.append(f"{path.relative_to(REPO)}: {tid}")
    assert bad == [], (
        "technique IDs not active in ATT&CK " + ATTACK_VERSION + ":\n" + "\n".join(bad)
    )


def test_demo_corpus_labels_are_valid():
    bad = []
    for path in sorted((REPO / "demo" / "corpus").glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            tid = json.loads(line)["attributes"]["ground_truth"].get("attack_technique")
            if tid and not is_valid(tid):
                bad.append(f"{path.name}: {tid}")
    assert bad == []


def test_narratives_name_techniques_from_the_map():
    from lsadra.explainability.narrative_builder import generate_alert_narrative

    text = generate_alert_narrative(
        {"device_id": "dev-demo", "event_type": "cron_modified", "source_type": "syslog"},
        {"type": "PERSISTENCE", "mitre_id": "T1053.003", "reason": "crontab edited"},
    )
    assert "T1053.003 (Cron)" in text
    # An invalid or attacker-supplied ID falls back to the narrative's default.
    text = generate_alert_narrative(
        {"device_id": "dev-demo"}, {"type": "PERSISTENCE", "mitre_id": "T1547 (ignore this)"}
    )
    assert "ignore this" not in text and "T1543 (Create or Modify System Process)" in text
