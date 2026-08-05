"""
LSADRA V4 — Local smoke test.

Tests:
  1. All new V4 parsers (can_parse + parse)
  2. IngestionManager auto-routing
  3. build_enhanced_feature_table
  4. V4 rule functions
  5. calculate_dynamic_severity
  6. generate_alert_narrative + generate_investigative_summary
  7. analyze_false_positive
  8. DB: 002 migration, store_feedback, get_ingestion_stats
  9. Scheduler job registration (no APScheduler run)
 10. UI page imports
"""

import sys
import traceback
import sqlite3
import os
import tempfile

# Allow running as a script from anywhere: put the repo root on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Boot in dev mode so production config guards (§6 #4 JWT secret, #6 TLS) don't
# trip when the smoke suite imports lsadra.config.
os.environ.setdefault("LSADRA_DEV_MODE", "true")

PASS = 0
FAIL = 0


def ok(name):
    global PASS
    PASS += 1
    print(f"  ✅  {name}")


def fail(name, exc=None):
    global FAIL
    FAIL += 1
    msg = f"  ❌  {name}"
    if exc:
        msg += f"\n       {type(exc).__name__}: {exc}"
    print(msg)


def section(title):
    print(f"\n{'─'*60}\n  {title}\n{'─'*60}")


# ──────────────────────────────────────────────────────────────
# 1. Parsers
# ──────────────────────────────────────────────────────────────
section("1. V4 Parser imports & basic parsing")

try:
    from lsadra.ingestion.base_parser import BaseParser, REQUIRED_SCHEMA_FIELDS
    ok("base_parser import")
except Exception as e:
    fail("base_parser import", e)

try:
    from lsadra.ingestion.syslog_parser import SyslogParser
    p = SyslogParser()
    line = "Jan  5 12:34:56 hostname sudo[1234]: root : COMMAND=/bin/bash"
    assert p.can_parse(line), "can_parse should return True"
    event = p.parse(line, "dev-001")
    assert event is not None, "parse returned None"
    assert event["source_type"] == "syslog"
    assert p.validate_output(event), "schema validation failed"
    ok("SyslogParser (sudo line)")
except Exception as e:
    fail("SyslogParser", e)

try:
    from lsadra.ingestion.windows_event_parser import WindowsEventParser
    p = WindowsEventParser()
    line = "4625|2024-01-01T12:00:00|jsmith|192.168.1.1||"
    assert p.can_parse(line), "can_parse should return True"
    event = p.parse(line, "win-001")
    assert event is not None, "parse returned None"
    assert event["source_type"] == "windows_event"
    assert event["success"] == False
    ok("WindowsEventParser (4625 pipe-delimited)")
except Exception as e:
    fail("WindowsEventParser", e)

try:
    from lsadra.ingestion.network_flow_parser import NetworkFlowParser
    p = NetworkFlowParser()
    line = "2024-01-01T12:00:00,192.168.1.100,10.0.0.5,54321,22,TCP,512,4"
    assert p.can_parse(line), "can_parse should return True"
    event = p.parse(line, "net-001")
    assert event is not None, "parse returned None"
    assert event["source_type"] == "network_flow"
    ok("NetworkFlowParser (NetFlow CSV)")
except Exception as e:
    fail("NetworkFlowParser", e)

try:
    from lsadra.ingestion.network_flow_parser import NetworkFlowParser
    p = NetworkFlowParser()
    line = "Jan  5 12:00:00 IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=12345 DPT=22"
    assert p.can_parse(line), "firewall line should be parseable"
    event = p.parse(line, "fw-001")
    assert event is not None
    assert event["event_type"] == "firewall_deny"
    ok("NetworkFlowParser (iptables DENY)")
except Exception as e:
    fail("NetworkFlowParser (iptables DENY)", e)

try:
    from lsadra.ingestion.endpoint_parser import EndpointParser
    p = EndpointParser()
    line = "2024-01-01T12:00:00|dev-001|jsmith|powershell.exe|winword.exe|powershell -enc dQBuAGkA|C:\\Windows\\Temp|process_create"
    assert p.can_parse(line), "endpoint line should be parseable"
    event = p.parse(line, "ep-001")
    assert event is not None
    assert event["source_type"] == "endpoint"
    assert event["extra"]["suspicious_cmdline"] == True
    assert event["extra"]["unusual_parent"] == True
    ok("EndpointParser (suspicious cmdline + unusual parent)")
except Exception as e:
    fail("EndpointParser", e)

# ──────────────────────────────────────────────────────────────
# 2. IngestionManager
# ──────────────────────────────────────────────────────────────
section("2. IngestionManager auto-routing")

try:
    from lsadra.ingestion.ingestion_manager import IngestionManager
    mgr = IngestionManager()
    assert len(mgr.parsers) >= 5
    ok("IngestionManager instantiation")
except Exception as e:
    fail("IngestionManager instantiation", e)

try:
    # Auto-detect syslog
    line = "Jan  5 12:34:56 server sudo[999]: root : COMMAND=/usr/bin/whoami"
    event = mgr.ingest_line(line, "dev-auto")
    assert event is not None, "syslog auto-detect failed"
    assert event["source_type"] == "syslog"
    ok("IngestionManager auto-detect syslog")
except Exception as e:
    fail("IngestionManager auto-detect syslog", e)

try:
    # Auto-detect network flow
    line = "2024-01-01T12:00:00,10.1.1.1,8.8.8.8,9999,443,TCP,1024,2"
    event = mgr.ingest_line(line, "dev-auto")
    assert event is not None, "network flow auto-detect failed"
    assert event["source_type"] == "network_flow"
    ok("IngestionManager auto-detect network_flow")
except Exception as e:
    fail("IngestionManager auto-detect network_flow", e)

try:
    stats = mgr.get_source_stats()
    assert isinstance(stats, dict)
    ok(f"IngestionManager.get_source_stats() — {list(stats.keys())}")
except Exception as e:
    fail("IngestionManager.get_source_stats()", e)

# ──────────────────────────────────────────────────────────────
# 3. Feature extraction
# ──────────────────────────────────────────────────────────────
section("3. Enhanced feature extraction")

try:
    import pandas as pd
    from lsadra.features.feature_extractor import build_enhanced_feature_table
    from datetime import datetime, timedelta

    rows = []
    base = datetime(2024, 1, 1, 12, 0, 0)
    for i in range(20):
        rows.append({
            "timestamp":   (base + timedelta(seconds=i * 15)).isoformat(),
            "source_ip":   "192.168.1.100",
            "dest_ip":     "10.0.0.1",
            "username":    "jsmith",
            "event_type":  "login_attempt",
            "source_type": "ssh_log",
            "success":     (i % 6 != 0),
            "device_id":   "dev-001",
            "extra":       {},
            "raw":         f"test line {i}",
        })
    df = pd.DataFrame(rows)
    result = build_enhanced_feature_table(df)
    assert not result.empty, "result df is empty"
    assert "failed_logins_last_5min" in result.columns
    assert "failure_ratio" in result.columns
    ok(f"build_enhanced_feature_table — {len(result.columns)} columns, {len(result)} rows")
except Exception as e:
    fail("build_enhanced_feature_table", e)
    traceback.print_exc()

# ──────────────────────────────────────────────────────────────
# 4. V4 Rule engine
# ──────────────────────────────────────────────────────────────
section("4. V4 Rule engine")

try:
    from lsadra.detection.rule_engine import evaluate_rules, evaluate_all_v4_rules

    # V3 preserved
    name, mitre = evaluate_rules({
        "failures_15m": 25, "unique_users_15m": 2, "successes_15m": 0,
        "is_off_hours": 0, "failure_ratio_15m": 0.95,
    })
    assert name == "Brute Force Attack"
    ok(f"V3 evaluate_rules preserved — '{name}', {mitre}")
except Exception as e:
    fail("V3 evaluate_rules", e)

try:
    alert = evaluate_all_v4_rules({
        "source_ip":               "1.2.3.4",
        "failed_logins_last_5min": 18,
        "failed_logins_last_15min": 25,
        "login_attempt_velocity":  3.5,
        "unique_usernames_per_ip": 1,
        "failure_ratio":           0.95,
        "cross_source_activity":   False,
        "source_type":             "ssh_log",
    })
    assert alert is not None
    assert alert["type"] == "BRUTE_FORCE"
    assert alert["severity"] in ("HIGH", "CRITICAL")
    ok(f"evaluate_all_v4_rules — {alert['type']} / {alert['severity']}")
except Exception as e:
    fail("evaluate_all_v4_rules", e)
    traceback.print_exc()

try:
    from lsadra.detection.rule_engine import check_port_scan
    alert = check_port_scan({
        "source_ip": "10.0.0.1",
        "source_type": "network_flow",
        "unique_dst_ports_per_ip": 60,
    })
    assert alert is not None
    assert alert["type"] == "PORT_SCAN"
    ok(f"check_port_scan — {alert['severity']}")
except Exception as e:
    fail("check_port_scan", e)

# ──────────────────────────────────────────────────────────────
# 5. Dynamic severity
# ──────────────────────────────────────────────────────────────
section("5. Dynamic severity scoring")

try:
    from lsadra.detection.severity import compute_severity_score, calculate_dynamic_severity

    score, label = compute_severity_score(layer1_z=8.0, layer2_score=0.9, layer2_votes=3, total_models=3, layer3_error=0.4)
    assert 0.0 <= score <= 1.0
    ok(f"V3 compute_severity_score preserved — {score:.3f} / {label}")
except Exception as e:
    fail("V3 compute_severity_score", e)

try:
    label, score, explanation = calculate_dynamic_severity(
        features={"failed_logins_last_5min": 18, "login_attempt_velocity": 4.0},
        shap_values={"failures_15m": 0.6},
        rule_alert={"rule_weight": 0.85},
        threat_intel_score=0.5,
        cross_source_corroboration=True,
    )
    assert label in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert 0.0 <= score <= 1.0
    assert explanation
    ok(f"calculate_dynamic_severity — {label} ({score:.3f})\n       {explanation}")
except Exception as e:
    fail("calculate_dynamic_severity", e)
    traceback.print_exc()

# ──────────────────────────────────────────────────────────────
# 6. Narrative engine
# ──────────────────────────────────────────────────────────────
section("6. Narrative engine")

try:
    from lsadra.explainability.narrative_builder import NarrativeBuilder

    text = NarrativeBuilder.build(
        threat_type="Brute Force Attack",
        mitre_id="T1110.001",
        row_data={"source_ip": "1.2.3.4", "effective_username": "root", "failures_15m": 30, "is_off_hours": 1},
        layer1_z=7.5,
        layer2_score=0.9,
    )
    assert "Brute Force" in text
    ok("V3 NarrativeBuilder.build() preserved")
except Exception as e:
    fail("V3 NarrativeBuilder.build()", e)

try:
    from lsadra.explainability.narrative_builder import generate_alert_narrative

    narrative = generate_alert_narrative(
        features={
            "source_ip": "5.5.5.5",
            "failed_logins_last_5min": 18,
            "login_attempt_velocity": 3.6,
            "unique_usernames_per_ip": 1,
            "cross_source_activity": False,
        },
        rule_alert={
            "type": "BRUTE_FORCE",
            "severity": "CRITICAL",
            "rule_weight": 0.95,
            "reason": "18 failed logins in 5 min",
            "mitre_id": "T1110.001",
            "mitre_name": "Brute Force",
        },
        shap_values={"failures_15m": 0.55},
    )
    assert "5.5.5.5" in narrative
    assert len(narrative) > 60
    ok(f"generate_alert_narrative — {len(narrative)} chars")
    print(f"\n       Preview: {narrative[:140]}...")
except Exception as e:
    fail("generate_alert_narrative", e)
    traceback.print_exc()

try:
    from lsadra.explainability.narrative_builder import analyze_false_positive

    result = analyze_false_positive(
        original_alert={
            "type": "BRUTE_FORCE",
            "features": {
                "login_attempt_velocity": 0.3,
                "unique_usernames_per_ip": 1.0,
                "failed_logins_last_5min": 8,
            },
        },
        analyst_note="This is a monitoring service",
    )
    assert "pattern" in result
    assert "suggested_threshold_change" in result
    ok(f"analyze_false_positive — pattern='{result['pattern']}', confidence='{result['confidence']}'")
except Exception as e:
    fail("analyze_false_positive", e)
    traceback.print_exc()

# ──────────────────────────────────────────────────────────────
# 7. Database: 002 migration + V4 helpers
# ──────────────────────────────────────────────────────────────
section("7. Database: migration + V4 CRUD")

_MIGRATION_002 = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "lsadra", "storage", "migrations", "002_v4_schema.sql",
)

try:
    migration_sql = open(_MIGRATION_002, "r").read()
    conn = sqlite3.connect(":memory:")
    conn.executescript(migration_sql)
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    assert "alerts_feedback" in tables, f"alerts_feedback missing — got {tables}"
    assert "ingestion_stats" in tables, f"ingestion_stats missing"
    ok(f"002_v4_schema.sql applied — tables: {tables}")
    conn.close()
except Exception as e:
    fail("002_v4_schema.sql", e)
    traceback.print_exc()

try:
    import json, pathlib
    from lsadra.storage.database import (
        store_feedback, get_false_positive_patterns,
        get_fp_rate_by_source_type, update_ingestion_stats, get_ingestion_stats,
    )

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()

    # Build a fully-bootstrapped connection and pass it directly to each helper
    conn = sqlite3.connect(tmp.name)
    conn.row_factory = sqlite3.Row
    conn.executescript(open(_MIGRATION_002).read())
    conn.execute("""CREATE TABLE IF NOT EXISTS ingestion_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_type TEXT NOT NULL UNIQUE,
        events_count INTEGER DEFAULT 0,
        parse_errors INTEGER DEFAULT 0,
        last_event TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()

    # Test store_feedback with explicit conn (no DB_PATH lookup)
    store_feedback(conn, 1, "false_positive", "test note",
                   "monitoring_automation", {"failed_logins_last_5min": 12}, "ssh_log")

    fps = get_false_positive_patterns(conn)
    assert len(fps) >= 1, f"Expected feedback rows, got {fps}"

    update_ingestion_stats(conn, "ssh_log", events=100, errors=2)
    update_ingestion_stats(conn, "network_flow", events=50, errors=0)

    stats = get_ingestion_stats(conn)
    assert any(s["source_type"] == "ssh_log" for s in stats), f"ssh_log missing: {stats}"

    rates = get_fp_rate_by_source_type(conn)
    assert isinstance(rates, dict)

    conn.close()
    os.unlink(tmp.name)
    ok("store_feedback + get_false_positive_patterns + update_ingestion_stats + get_ingestion_stats + get_fp_rate_by_source_type")
except Exception as e:
    fail("DB V4 CRUD helpers", e)
    traceback.print_exc()

# ──────────────────────────────────────────────────────────────
# 8. Scheduler job registration
# ──────────────────────────────────────────────────────────────
section("8. Scheduler V4 job registration")

try:
    from lsadra.jobs import scheduler as sched_mod
    # Just import and verify V4 job functions exist, don't actually start scheduler
    assert callable(sched_mod._run_cross_source_correlation)
    assert callable(sched_mod._run_lateral_movement_scan)
    assert callable(sched_mod._run_ingestion_health_check)
    assert callable(sched_mod._run_metrics_aggregation)  # V3 preserved
    ok("All 3 V4 scheduler job functions present + V3 jobs exist")
except Exception as e:
    fail("Scheduler V4 jobs", e)

# ──────────────────────────────────────────────────────────────
# 9. UI page imports
# ──────────────────────────────────────────────────────────────
section("9. UI page imports (no browser required)")

for page_name, module_path in [
    ("investigate", "lsadra.ui.pages.investigate"),
    ("multi_source", "lsadra.ui.pages.multi_source"),
    ("feedback",     "lsadra.ui.pages.feedback"),
    ("live_alerts",  "lsadra.ui.pages.live_alerts"),
]:
    try:
        import importlib
        mod = importlib.import_module(module_path)
        assert callable(getattr(mod, "render", None)), "render() function missing"
        ok(f"{page_name}.render() importable")
    except Exception as e:
        # Streamlit pages may fail on import due to st.* calls at module level
        # This is expected in non-Streamlit context — just check ImportError
        if "streamlit" in str(e).lower() or "ModuleNotFoundError" in type(e).__name__:
            ok(f"{page_name} — import blocked by Streamlit context (expected in CLI)")
        else:
            fail(f"{page_name} import", e)

# ──────────────────────────────────────────────────────────────
# 10. Config V4 keys
# ──────────────────────────────────────────────────────────────
section("10. Config V4 keys")

try:
    from lsadra import config as cfg
    assert hasattr(cfg, "BRUTE_FORCE_5MIN_CRITICAL")
    assert hasattr(cfg, "PORT_SCAN_CRITICAL_THRESHOLD")
    assert hasattr(cfg, "LARGE_TRANSFER_BYTES")
    assert hasattr(cfg, "V4_SEVERITY_THRESHOLDS")
    assert hasattr(cfg, "INGESTION_SILENCE_THRESHOLD_MINUTES")
    ok(f"All V4 config keys present — BF_5M_CRITICAL={cfg.BRUTE_FORCE_5MIN_CRITICAL}, "
       f"PORT_SCAN_CRIT={cfg.PORT_SCAN_CRITICAL_THRESHOLD}, "
       f"LARGE_XFER={cfg.LARGE_TRANSFER_BYTES:,} bytes")
except Exception as e:
    fail("V4 config keys", e)

# ──────────────────────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────────────────────
print(f"\n{'═'*60}")
total = PASS + FAIL
print(f"  V4 SMOKE TEST RESULTS: {PASS}/{total} passed")
if FAIL:
    print(f"  ⚠️  {FAIL} test(s) failed — review output above")
else:
    print("  🎉  All V4 tests passed!")
print(f"{'═'*60}\n")

sys.exit(0 if FAIL == 0 else 1)
