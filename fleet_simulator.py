"""
LSADRA V3 — Fleet Simulator

Simulates multiple devices to fully populate all dashboard tabs.
Cleans the database on start so it generates a fresh view every time.

Usage:
    1. Start the API server:  python -m uvicorn server:app --host 0.0.0.0 --port 8000
    2. Start the dashboard:   python -m streamlit run lsadra/ui/dashboard.py
    3. Run this simulator:    python fleet_simulator.py
"""

import json
import sys
import time
import random
import threading
import uuid
import requests
from datetime import datetime, timezone, timedelta

SERVER_URL = "http://127.0.0.1:8000"

# Diverse hostnames and OS combinations
DEVICE_PROFILES = [
    {"hostname": "ubuntu-web-prod", "os_type": "linux"},
    {"hostname": "win-db-primary", "os_type": "windows"},
    {"hostname": "centos-app-1", "os_type": "linux"},
    {"hostname": "win-jump-box", "os_type": "windows"},
    {"hostname": "alpine-worker-1", "os_type": "linux"},
]

# Attacker IPs (public-looking for Threat Intel)
ATTACKER_IPS = [
    "185.15.202.13",
    "45.33.32.156",
    "103.20.150.2",
    "89.187.160.10",
]

NORMAL_USERS = ["admin", "root", "ubuntu", "db_operator", "developer"]

print("=" * 60)
print("🚀 LSADRA V3 Fleet Simulator")
print("=" * 60)

# ── Step 1: Verify server is running ─────────────────────────────────────
print("\n1. Checking server...")
try:
    resp = requests.get(f"{SERVER_URL}/api/health", timeout=5)
    if resp.status_code != 200:
        print("❌ Server not healthy. Start it first:")
        print("   python -m uvicorn server:app --host 0.0.0.0 --port 8000")
        sys.exit(1)
    print(f"   ✅ Server is running (v{resp.json().get('version', '?')})")
except Exception:
    print("❌ Cannot reach server. Start it first:")
    print("   python -m uvicorn server:app --host 0.0.0.0 --port 8000")
    sys.exit(1)

# ── Step 2: Wipe DB for fresh start ──────────────────────────────────────
print("\n2. Cleaning database for a fresh run...")
from lsadra.storage.database import init_db, get_connection
init_db()

conn = get_connection()
cur = conn.cursor()
cur.execute("PRAGMA foreign_keys=OFF")
for table in [
    "anomalies", "incidents", "normalized_events",
    "device_heartbeats", "metrics_5min", "model_registry",
    "feature_drift", "threat_intel_cache", "ip_geolocation",
    "devices", "onboarding_tokens",
]:
    try:
        cur.execute(f"DELETE FROM {table}")
    except Exception:
        pass
conn.commit()
cur.execute("PRAGMA foreign_keys=ON")

# Ensure admin user exists
cur.execute("SELECT id FROM users LIMIT 1")
row = cur.fetchone()
if not row:
    from lsadra.auth import hash_password
    from lsadra.storage.database import create_user
    admin_id = str(uuid.uuid4())
    create_user(admin_id, "admin", hash_password("admin"), "ADMIN")
    user_id = admin_id
else:
    user_id = row[0]
conn.close()
print("   ✅ Database cleaned.")

# ── Step 3: Register all devices ─────────────────────────────────────────
print("\n3. Registering 5 devices...")
from lsadra.onboarding.token_manager import generate_token

devices = []
for profile in DEVICE_PROFILES:
    token = generate_token(user_id)  # Each device needs its own single-use token
    resp = requests.post(f"{SERVER_URL}/api/devices/register", json={
        "token": token,
        "hostname": profile["hostname"],
        "os_type": profile["os_type"],
    })
    if resp.status_code == 200:
        data = resp.json()
        devices.append({
            "device_id": data["device_id"],
            "api_key": data["api_key"],
            "hostname": profile["hostname"],
        })
        print(f"   ✅ {profile['hostname']} ({data['device_id'][:8]}...)")
    else:
        print(f"   ❌ {profile['hostname']}: {resp.text}")

if not devices:
    print("No devices registered. Exiting.")
    sys.exit(1)


# ── Helper: send events via the API ──────────────────────────────────────

def send_events(device, events):
    """Send a list of event dicts to the API for a specific device."""
    headers = {
        "x-device-id": device["device_id"],
        "x-api-key": device["api_key"],
    }
    payload = {"events": events}
    try:
        resp = requests.post(
            f"{SERVER_URL}/api/events/batch",
            json=payload,
            headers=headers,
            timeout=15,
        )
        return resp.status_code == 200
    except Exception:
        return False


def make_event(device, event_type="auth_success", username=None, source_ip=None, ts=None):
    """Create a single event dict."""
    return {
        "schema_version": "1",  # event contract v1 (docs/contracts/event-schema.v1.json)
        "timestamp": (ts or datetime.now(timezone.utc)).isoformat(),
        "host": device["hostname"],
        "effective_username": username or random.choice(NORMAL_USERS),
        "source_ip": source_ip or f"192.168.1.{random.randint(10, 50)}",
        "event_type": event_type,
        "raw_message": f"{'Accepted' if event_type == 'auth_success' else 'Failed'} password for {username or 'user'}",
        "attributes": {},
    }


# ── Step 4: Establish baselines (250 events per device) ──────────────────
print("\n4. Establishing baselines (250 normal events per device)...")
base_time = datetime.now(timezone.utc) - timedelta(hours=2)

for device in devices:
    batch = []
    for i in range(250):
        ts = base_time + timedelta(seconds=i * 28)  # Spread over 2 hours
        evt = make_event(
            device,
            event_type="auth_success" if random.random() > 0.1 else "auth_failure",
            source_ip=f"192.168.1.{random.randint(10, 50)}",
            ts=ts,
        )
        batch.append(evt)

        if len(batch) == 50:
            ok = send_events(device, batch)
            batch = []

    print(f"   [{device['hostname']}] ✅ 250 baseline events sent")

# ── Step 5: Inject historical attacks (to populate Live Alerts immediately) ───
print("\n5. Injecting attacks across devices to create anomalies & incidents...")
for device in devices:
    bad_ip = random.choice(ATTACKER_IPS)
    user = random.choice(NORMAL_USERS)

    # Concentrated brute force: 15 failures in rapid succession
    attack_events = []
    attack_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(5, 30))
    for j in range(15):
        evt = make_event(
            device,
            event_type="auth_failure",
            username=user,
            source_ip=bad_ip,
            ts=attack_time + timedelta(seconds=j),
        )
        attack_events.append(evt)

    ok = send_events(device, attack_events)
    status = "✅" if ok else "❌"
    print(f"   [{device['hostname']}] {status} Brute force from {bad_ip} ({user})")

# ── Step 6: Force metrics aggregation ────────────────────────────────────
print("\n6. Forcing metrics aggregation...")
try:
    from lsadra.storage.metrics_aggregator import run as run_metrics
    run_metrics()
    print("   ✅ Metrics aggregated for Analytics tab")
except Exception as e:
    print(f"   ⚠️ Metrics aggregation: {e}")

# ── Step 7: Show what's in the DB now ────────────────────────────────────
print("\n7. Verifying data in database...")
conn = get_connection()
event_count = conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
anomaly_count = conn.execute("SELECT COUNT(*) FROM anomalies WHERE is_anomaly = 1").fetchone()[0]
incident_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
device_count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
metrics_count = conn.execute("SELECT COUNT(*) FROM metrics_5min").fetchone()[0]
conn.close()

print(f"   📊 Events:    {event_count}")
print(f"   ⚡ Anomalies: {anomaly_count}")
print(f"   📋 Incidents: {incident_count}")
print(f"   🖥️  Devices:   {device_count}")
print(f"   📈 Metrics:   {metrics_count} windows")


# ── Step 8: Start background heartbeats ──────────────────────────────────
def heartbeat_loop():
    while True:
        for d in devices:
            try:
                requests.post(f"{SERVER_URL}/heartbeat", json={
                    "device_id": d["device_id"],
                    "cpu_pct": round(random.uniform(10, 85), 1),
                    "mem_pct": round(random.uniform(20, 95), 1),
                    "agent_version": "3.0.0",
                }, timeout=3)
            except Exception:
                pass
        time.sleep(15)

hb_thread = threading.Thread(target=heartbeat_loop, daemon=True)
hb_thread.start()
print("\n💓 Heartbeats started (every 15s for all 5 devices).")


# ── Step 9: Continuous live traffic ──────────────────────────────────────
def live_traffic(device):
    while True:
        if random.random() > 0.08:
            # Normal event
            evt = make_event(device, event_type="auth_success")
            send_events(device, [evt])
            time.sleep(random.uniform(3, 8))
        else:
            # Random attack burst
            bad_ip = random.choice(ATTACKER_IPS)
            user = random.choice(NORMAL_USERS)
            print(f"   [{device['hostname']}] 🚨 LIVE ATTACK from {bad_ip}")
            attack = [
                make_event(device, "auth_failure", username=user, source_ip=bad_ip)
                for _ in range(15)
            ]
            send_events(device, attack)

            # Re-aggregate metrics after attack
            try:
                from lsadra.storage.metrics_aggregator import run as run_metrics
                run_metrics()
            except Exception:
                pass

            time.sleep(random.uniform(20, 40))

print("\n🔥 Starting live traffic across all devices...")
for d in devices:
    t = threading.Thread(target=live_traffic, args=(d,), daemon=True)
    t.start()

print("\n" + "=" * 60)
print("✅ Fleet simulator running!")
print("   Dashboard:  http://localhost:8501")
print("   API docs:   http://127.0.0.1:8000/docs")
print("   Press Ctrl+C to stop.")
print("=" * 60 + "\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nShutting down simulator...")
