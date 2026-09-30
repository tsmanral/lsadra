"""
Isolated DB V4 CRUD smoke test.
Patches DB_PATH to a temp file with the V4 schema pre-applied.
"""
import os, sys, sqlite3, tempfile, json

# Allow running as a script from anywhere: put the repo root on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── patch DB_PATH before any import ─────────────────────────
tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp.close()

import lsadra.config as cfg_mod
import pathlib
cfg_mod.DB_PATH = pathlib.Path(tmp.name)
# database.py binds DB_PATH at import (`from lsadra.config import DB_PATH`), and
# earlier test modules may already have imported it: patch that binding too.
import lsadra.storage.database as db_mod
db_mod.DB_PATH = pathlib.Path(tmp.name)

# Apply V4 schema
conn = sqlite3.connect(tmp.name)
conn.executescript(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lsadra", "storage", "migrations", "002_v4_schema.sql")).read())
# Also create the normalized_events and anomalies tables so foreign keys work
conn.executescript("""
CREATE TABLE IF NOT EXISTS normalized_events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, device_id TEXT, user_id TEXT, host TEXT, effective_username TEXT, source_ip TEXT, event_type TEXT, raw_message TEXT, attributes TEXT, is_synthetic INTEGER);
CREATE TABLE IF NOT EXISTS anomalies (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS ingestion_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, source_type TEXT UNIQUE, events_count INTEGER DEFAULT 0, parse_errors INTEGER DEFAULT 0, last_event TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS alerts_feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER, label TEXT CHECK(label IN ('true_positive','false_positive')), analyst_note TEXT, fp_pattern TEXT, suggested_thresholds TEXT, source_type TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
""")
conn.commit()
conn.close()

print(f"Temp DB: {tmp.name}")
print("Schema applied.")

# ── now import the functions ──────────────────────────────────
from lsadra.storage.database import (
    store_feedback,
    get_false_positive_patterns,
    get_fp_rate_by_source_type,
    update_ingestion_stats,
    get_ingestion_stats,
)

print("Functions imported.")

# store_feedback
store_feedback(None, 1, "false_positive", "test note", "monitoring_automation",
               {"failed_logins_last_5min": 12}, "ssh_log")
print("store_feedback: OK")

# get_false_positive_patterns
fps = get_false_positive_patterns()
print(f"get_false_positive_patterns: {len(fps)} rows — {fps}")

# update_ingestion_stats
update_ingestion_stats(None, "ssh_log", events=100, errors=2)
update_ingestion_stats(None, "network_flow", events=50, errors=0)
print("update_ingestion_stats: OK")

# get_ingestion_stats
stats = get_ingestion_stats()
print(f"get_ingestion_stats: {stats}")
assert any(s["source_type"] == "ssh_log" for s in stats), "ssh_log missing from stats"

# get_fp_rate_by_source_type
rates = get_fp_rate_by_source_type()
print(f"get_fp_rate_by_source_type: {rates}")

os.unlink(tmp.name)
print("\n✅ All DB V4 CRUD functions work correctly.")
