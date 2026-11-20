"""
LSADRA V3 — Windows Agent + Server Simulator.

This script makes it easy to test the V3 pipeline locally on Windows.
1. Starts the FastAPI server (`server.py`) in the background.
2. Waits for it to boot.
3. Grabs a user from the DB and generates a registration token.
4. Registers a fake Windows device with the API.
5. Starts sending heartbeats and tailing a `dummy_auth.log` file.
"""

import os
import subprocess
import time
import threading
import requests
import sqlite3
import sys

SERVER_URL = "http://127.0.0.1:8000"

print("=" * 70)
print("🛡️  LSADRA V3 — Windows Agent Simulator")
print("=" * 70)

print("\n1. Starting FastAPI Server in the background...")
server_proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "server:app"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

# Give the server 4 seconds to bind to port 8000
time.sleep(4)

# Verify server is running
try:
    resp = requests.get(f"{SERVER_URL}/api/health", timeout=5)
    if resp.status_code != 200:
        print("Error: Server health check failed.")
        server_proc.kill()
        exit(1)
    print(f"   ✅ Server is running (version: {resp.json().get('version', '?')})")
except Exception as e:
    print(f"Error: Could not connect to server: {e}")
    server_proc.kill()
    exit(1)

print("\n2. Looking up a user to generate a registration token...")
try:
    from lsadra.storage.database import init_db, get_connection
    from lsadra.onboarding.token_manager import generate_token

    init_db()

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users LIMIT 1")
    row = cur.fetchone()
    conn.close()

    if not row:
        print("   ⚠️  No users found. Creating a default admin user...")
        from lsadra.auth import hash_password
        from lsadra.storage.database import create_user
        import uuid

        admin_id = str(uuid.uuid4())
        create_user(admin_id, "admin", hash_password("admin"), "ADMIN")
        print("   ✅ Created user 'admin' (password: 'admin', role: ADMIN)")
        user_id = admin_id
    else:
        user_id = row[0]
        print(f"   ✅ Found user: {user_id[:8]}...")

    token = generate_token(user_id)
except Exception as e:
    print(f"Failed to generate token from DB: {e}")
    server_proc.kill()
    exit(1)

print("\n3. Registering 'Test-Windows-VM' with the API...")
try:
    resp = requests.post(
        f"{SERVER_URL}/api/devices/register",
        json={"token": token, "hostname": "Test-Windows-VM", "os_type": "windows"},
    )

    if resp.status_code != 200:
        print(f"   API Error ({resp.status_code}): {resp.text}")
        server_proc.kill()
        exit(1)

    device_data = resp.json()
    device_id = device_data["device_id"]
    api_key = device_data["api_key"]
    print(f"   ✅ Device registered: {device_id[:8]}...")
except Exception as e:
    print(f"Failed to communicate with API at {SERVER_URL}: {e}")
    server_proc.kill()
    exit(1)

# The API key is handed to the agent through LSADRA_AGENT_API_KEY when it is
# started below, so it is never written to agent_config.yml on disk.
print("\n4. Creating agent_config.yml and dummy_auth.log...")
config_yaml = f"""server_url: "{SERVER_URL}"
collector_endpoint: "/api/events/batch"
heartbeat_endpoint: "/heartbeat"
device_id: "{device_id}"
log_paths:
  - "dummy_auth.log"
batch_size: 1
flush_interval_seconds: 2
heartbeat_interval_seconds: 30
tls_verify: false
ca_cert_path: null
"""
with open("agent_config.yml", "w") as f:
    f.write(config_yaml)

with open("dummy_auth.log", "w") as f:
    f.write(
        "Mar 20 20:00:00 Test-PC sshd[123]: Accepted publickey for auth_user from 192.168.1.50 port 5555\n"
    )


# Start heartbeat thread
def send_heartbeats():
    """Background thread that sends periodic heartbeats."""
    while True:
        try:
            requests.post(
                f"{SERVER_URL}/heartbeat",
                headers={"X-Device-Id": device_id, "X-Api-Key": api_key},
                json={
                    "device_id": device_id,
                    "cpu_pct": 25.0,
                    "mem_pct": 45.0,
                    "agent_version": "3.0.0",
                },
                timeout=5,
            )
        except Exception:
            pass
        time.sleep(30)


heartbeat_thread = threading.Thread(target=send_heartbeats, daemon=True)
heartbeat_thread.start()

print("\n5. Starting the endpoint agent! (Press Ctrl+C to stop)")
print("=" * 70)
print("👉 INSTRUCTIONS:")
print("👉 Open 'dummy_auth.log' in Notepad.")
print("👉 Paste new SSH log lines into the file and save to trigger anomalies!")
print("👉 Heartbeats are being sent every 30 seconds.")
print("👉 Dashboard: cd frontend && npm run dev  (or the desktop app in desktop/)")
print(f"👉 API docs:  {SERVER_URL}/docs")
print("=" * 70)

try:
    subprocess.run(
        [sys.executable, "-m", "lsadra.endpoint_agent.linux_agent", "--config", "agent_config.yml"],
        env={**os.environ, "LSADRA_AGENT_API_KEY": api_key},
    )
except KeyboardInterrupt:
    pass
finally:
    print("\nShutting down API server...")
    server_proc.kill()
