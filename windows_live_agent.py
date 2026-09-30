import os
import subprocess
import time
import threading
import requests
import sqlite3
import sys
import xml.etree.ElementTree as ET
import re

SERVER_URL = "http://127.0.0.1:8000"
LOG_CHANNELS = ["Security", "System"]
POLL_INTERVAL_SEC = 5

def get_record_id(xml_text):
    """Extract EventRecordID from a Windows Event XML string."""
    try:
        root = ET.fromstring(xml_text)
        ns = ""
        m = re.match(r"\{(.*?)\}", root.tag)
        if m:
            ns = m.group(1)
        sys_path = ".//ns:System" if ns else ".//System"
        el = root.find(f"{sys_path}/ns:EventRecordID", {"ns": ns}) if ns else root.find(".//System/EventRecordID")
        if el is not None and el.text:
            return int(el.text)
    except Exception:
        pass
    return 0

def get_latest_record_id(channel):
    """Query wevtutil for the most recent EventRecordID in a channel."""
    try:
        res = subprocess.run(
            ["wevtutil", "qe", channel, "/c:1", "/rd:true", "/f:xml"],
            capture_output=True, text=True, check=True
        )
        if res.stdout.strip():
            return get_record_id(res.stdout.strip())
    except subprocess.CalledProcessError as e:
        if "Access is denied" in e.stderr:
            print(f"   \u26a0\ufe0f  Access Denied for '{channel}'. Run as Administrator to read this log.")
        else:
            print(f"   \u26a0\ufe0f  Failed to query '{channel}': {e.stderr.strip()}")
    except Exception as e:
        print(f"   \u26a0\ufe0f  Error getting latest record ID for {channel}: {e}")
    return 0

def fetch_new_events(channel, last_id):
    """Fetch all events with EventRecordID > last_id from a channel."""
    try:
        query = f"*[System[(EventRecordID > {last_id})]]"
        res = subprocess.run(
            ["wevtutil", "qe", channel, f"/q:{query}", "/f:xml", "/e:Events"],
            capture_output=True, text=True, check=True
        )
        if not res.stdout.strip():
            return []
        
        root = ET.fromstring(res.stdout.strip())
        events = []
        for child in root:
            xml_str = ET.tostring(child, encoding="unicode")
            events.append(xml_str)
        return events
    except Exception:
        return []

def main():
    print("=" * 70)
    print("\U0001f6e1\ufe0f  LSADRA V4 \u2014 LIVE Windows Agent")
    print("=" * 70)

    # 1. Check if server is running
    print("\n1. Checking V4 central API server...")
    try:
        resp = requests.get(f"{SERVER_URL}/api/health", timeout=5)
        if resp.status_code != 200:
            print("Server not healthy.")
            return
        print(f"   \u2705 Server is running (version: {resp.json().get('version', '?')})")
    except Exception as e:
        print("   \u274c Could not connect to API. Start the server first:")
        print("      $env:PYTHONPATH = (Get-Location).Path; .\\venv\\Scripts\\python -m uvicorn server:app")
        return

    # 2. Get DB Token
    print("\n2. Getting registration token...")
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
            print("   \u26a0\ufe0f  No users found. Creating a default admin user...")
            from lsadra.auth import hash_password
            from lsadra.storage.database import create_user
            import uuid
            user_id = str(uuid.uuid4())
            create_user(user_id, "admin", hash_password("admin"), "ADMIN")
            print("   \u2705 Created default 'admin' user.")
        else:
            user_id = row[0]
            print(f"   \u2705 Found admin user.")
            
        token = generate_token(user_id)
    except Exception as e:
        print(f"Failed to extract token: {e}")
        return

    # 3. Register device
    print("\n3. Registering Live Windows Machine...")
    try:
        hostname = os.environ.get('COMPUTERNAME', 'Windows-Live-Device')
        resp = requests.post(f"{SERVER_URL}/api/devices/register", json={
            "token": token,
            "hostname": hostname,
            "os_type": "windows"
        })
        
        if resp.status_code != 200:
            print(f"   \u274c API Error: {resp.text}")
            return
            
        data = resp.json()
        device_id = data['device_id']
        api_key = data['api_key']
        print(f"   \u2705 Registered successfully! Device ID: {device_id[:8]}...")
    except Exception as e:
        print(f"Failed to register device: {e}")
        return

    # 4. Start Heartbeats
    def send_heartbeats():
        while True:
            try:
                requests.post(f"{SERVER_URL}/heartbeat", json={
                    "device_id": device_id,
                    "cpu_pct": 10.0,
                    "mem_pct": 50.0,
                    "agent_version": "4.0.0",
                }, timeout=5)
            except Exception:
                pass
            time.sleep(30)

    threading.Thread(target=send_heartbeats, daemon=True).start()
    print("   \u2705 Heartbeat thread started.")

    # 5. Fetch Latest Event IDs
    print("\n4. Initialising Event Log Readers...")
    record_ids = {}
    for ch in LOG_CHANNELS:
        latest = get_latest_record_id(ch)
        record_ids[ch] = latest
        if latest > 0:
            print(f"   \u2705 Tailing '{ch}' starting at Record ID: {latest}")

    if record_ids.get("Security", 0) == 0:
        print("\n\u26a0\ufe0f  WARNING: Could not attach to the Security log.")
        print("   If you want to catch 4624/4625 Login Events, STOP this script and")
        print("   RE-RUN your terminal as ADMINISTRATOR.\n")

    print(f"\n5. Harvesting LIVE events... (Press Ctrl+C to stop)")
    print("=" * 70)
    
    headers = {
        "X-Device-Id": device_id,
        "X-Api-Key": api_key,
        "Content-Type": "application/json"
    }

    try:
        while True:
            for ch in LOG_CHANNELS:
                if record_ids[ch] == 0 and ch == "Security":
                    continue # Skip if no access

                events = fetch_new_events(ch, record_ids[ch])
                if events:
                    # Update bookmark
                    for ev in events:
                        rid = get_record_id(ev)
                        if rid > record_ids[ch]:
                            record_ids[ch] = rid
                    
                    # Push to V4 raw log API
                    # source_hint must be one of ssh|syslog|windows|network|endpoint.
                    lines = [{"raw_line": ev, "source_hint": "windows"} for ev in events]
                    
                    batch_size = 50
                    for i in range(0, len(lines), batch_size):
                        batch = {"lines": lines[i:i+batch_size]}
                        try:
                            res = requests.post(f"{SERVER_URL}/api/events/raw", json=batch, headers=headers)
                            if res.status_code == 200:
                                accepted = res.json().get('accepted', 0)
                                if accepted > 0:
                                    print(f"[{time.strftime('%X')}] Sent {accepted} parsed events from {ch}.")
                        except Exception as e:
                            print(f"Error sending batch: {e}")

            time.sleep(POLL_INTERVAL_SEC)
    except KeyboardInterrupt:
        print("\nShutting down LIVE Windows Agent.")

if __name__ == "__main__":
    main()
