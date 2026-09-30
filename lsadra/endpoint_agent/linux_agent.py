import os
import sys
import time
import json
import logging
import argparse
import ipaddress
import platform
import re
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime
from typing import List, Dict, Any, Optional

# Event contract v1 (docs/contracts/event-schema.v1.json). The agent must emit
# events the core accepts: a rejected event fails its whole batch with a 422.
SCHEMA_VERSION = "1"
_MAX_USERNAME, _MAX_HOST, _MAX_RAW, _MAX_ATTR_VALUE = 128, 255, 4096, 1024

# ── Logging Configuration ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("lsadra-agent")

# ── Configuration Defaults ───────────────────────────────────────────────
DEFAULT_CONFIG = {
    "server_url": "http://localhost:8000",
    "collector_endpoint": "/api/events/batch",
    "api_key": "",
    "device_id": platform.node(),
    "batch_size": 50,
    "flush_interval_seconds": 3,
    "log_paths": ["/var/log/auth.log"],
}

MAX_BACKOFF = 300  # 5 minutes

# ── Configuration Loader ─────────────────────────────────────────────────
def load_config(p: str) -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG.copy()
    if not os.path.exists(p):
        logger.warning("Config %s not found, using defaults.", p)
        return cfg

    # Minimal YAML-ish parser to avoid external dependencies like PyYAML
    loaded = {}
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                loaded[k.strip().strip('"')] = v.strip().strip('"')

    cfg.update(loaded)
    return cfg


# ── Simple SSH / sudo line parser ──────────────────────────────────────────

_AUTH_RE = re.compile(
    r"(Failed|Accepted)\s+(password|publickey)\s+(?:for invalid user\s+)?"
    r"(?:for\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
_SUDO_RE = re.compile(r"(\S+)\s*:\s*.*COMMAND=(.*)")

# Hybrid Syslog Regex (Supports BSD and ISO 8601 formats)
_SYSLOG_RE = re.compile(
    r"^(?:(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})|(?P<iso_ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^ ]*))\s+"
    r"(?P<host>\S+)\s+(?:\S+\[(?P<pid>\d+)\]:|\S+:)\s+(?P<message>.*)$"
)


def _parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a syslog line into a minimal event dict, or return None."""
    line = line.strip()
    if not line:
        return None

    m = _SYSLOG_RE.match(line)
    if not m:
        if "sudo" in line.lower() or "sshd" in line.lower() or "failed" in line.lower():
            logger.info("Line failed syslog regex but contains keywords: %s", line)
        return None

    g = m.groupdict()
    from datetime import datetime

    if g.get("iso_ts"):
        try:
            ts = datetime.fromisoformat(g["iso_ts"].replace('Z', '+00:00'))
        except ValueError:
            return None
    else:
        try:
            ts = datetime.strptime(
                f"{datetime.now().year} {g['month']} {g['day']} {g['time']}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            return None

    if ts.tzinfo is None:
        # BSD syslog carries no offset: the line was written in local time.
        ts = ts.astimezone()

    msg = g["message"]
    host = (g.get("host") or "")[:_MAX_HOST]

    # 1. Check for SSH Login attempts
    ma = _AUTH_RE.search(msg)
    if ma:
        status, method, user, src_ip, port = ma.groups()
        return {
            "schema_version": SCHEMA_VERSION,
            "timestamp": ts.isoformat(),
            "event_type": f"ssh_{status.lower()}_{method}",
            "host": host,
            "effective_username": user[:_MAX_USERNAME],
            "source_ip": _ip_or_none(src_ip),
            "raw_message": f"{status} {method} for {user} from {src_ip}:{port}"[:_MAX_RAW],
            "attributes": {
                "severity": "HIGH" if status == "Failed" else "INFO",
                "port": port
            }
        }

    # 2. Check for sudo commands
    ms = _SUDO_RE.search(msg)
    if ms:
        user, cmd = ms.groups()
        return {
            "schema_version": SCHEMA_VERSION,
            "timestamp": ts.isoformat(),
            "event_type": "sudo_command",
            "host": host,
            "effective_username": user[:_MAX_USERNAME],
            "raw_message": f"User {user} executed sudo: {cmd}"[:_MAX_RAW],
            "attributes": {
                "severity": "HIGH",
                "command": cmd[:_MAX_ATTR_VALUE]
            }
        }

    return None


def _ip_or_none(value: str) -> Optional[str]:
    """The contract takes an IPv4/IPv6 literal or null — sshd may log a hostname."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


# ── Batch Sender ─────────────────────────────────────────────────────────

def _send_batch(events: List[Dict[str, Any]], server_url: str, endpoint: str, device_id: str, api_key: str) -> bool:
    url = f"{server_url.rstrip('/')}{endpoint}"
    # The batch envelope is exactly {"events": [...]}; the device identity
    # travels in the X-Device-Id header (the core rejects unknown keys).
    payload = json.dumps({"events": events}).encode("utf-8")
    
    headers = {
        "X-Device-Id": device_id,
        "X-API-Key": api_key,
        "Content-Type": "application/json"
    }
    backoff = 2
    
    while True:
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    logger.info("Successfully sent batch of %d events to %s", len(events), url)
                    return True
                logger.error("Server rejected batch (%d)", response.status)
                return False
        except urllib.error.HTTPError as exc:
            if exc.code == 422:
                # Event-contract rejection: resending the same bytes can never
                # succeed, and retrying forever would stall the tailer.
                logger.error("Server rejected batch as invalid (422), dropping it: %.500s",
                             exc.read().decode("utf-8", "replace"))
                return False
            logger.warning("Send failed (%s), retrying in %ds ...", exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF)
        except Exception as exc:
            logger.warning("Send failed (%s), retrying in %ds ...", exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF)


# ── File tailer ───────────────────────────────────────────────────────────

def _tail(path: str, batch_size: int, flush_interval: float, cfg: Dict[str, Any]):
    logger.info("Tailing %s  (batch=%d, flush=%ds)", path, batch_size, flush_interval)
    buffer: List[Dict[str, Any]] = []
    last_flush = time.time()

    if not os.path.exists(path):
        logger.error("File %s does not exist. Cannot tail.", path)
        return

    with open(path, "r") as f:
        # Seek near end for demo continuity
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if line:
                ev = _parse_line(line)
                if ev:
                    logger.info("Captured relevant event: %s", ev.get('event_type'))
                    buffer.append(ev)

            now = time.time()
            if (len(buffer) >= batch_size) or (buffer and now - last_flush >= flush_interval):
                _send_batch(buffer, cfg["server_url"], cfg["collector_endpoint"], cfg["device_id"], cfg["api_key"])
                buffer.clear()
                last_flush = now

            if not line:
                time.sleep(0.5)


# ── Journal tailer ────────────────────────────────────────────────────────

def _tail_journal(batch_size: int, flush_interval: float, cfg: Dict[str, Any]):
    import subprocess
    
    logger.info("Starting journalctl tailing (modern source)...")
    # -n 0 ensures we ONLY see events that happen AFTER the agent starts (Clean Demo)
    cmd = ["journalctl", "-f", "-n", "0", "-o", "short"]
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        logger.error("Failed to start journalctl: %s", e)
        return

    buffer = []
    last_flush = time.time()

    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
                continue

            ev = _parse_line(line)
            if ev:
                logger.info("Captured relevant event from journal: %s", ev.get('event_type'))
                buffer.append(ev)

            now = time.time()
            if (len(buffer) >= batch_size) or (now - last_flush >= flush_interval and buffer):
                if _send_batch(buffer, cfg["server_url"], cfg["collector_endpoint"], cfg["device_id"], cfg["api_key"]):
                    buffer.clear()
                    last_flush = now
    except KeyboardInterrupt:
        proc.terminate()
    finally:
        proc.kill()


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LSADRA Linux Endpoint Agent")
    parser.add_argument("--config", default="/etc/lsadra-agent/config.yml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if not cfg.get("device_id") or not cfg.get("api_key"):
        logger.error("device_id and api_key must be set in config.")
        sys.exit(1)

    batch_size = int(cfg.get("batch_size", 50))
    flush_interval = float(cfg.get("flush_interval_seconds", 2))

    auth_log = "/var/log/auth.log"
    use_journal = False
    import shutil
    if shutil.which("journalctl"):
        use_journal = True
    elif not os.path.exists(auth_log):
        use_journal = True
    else:
        mtime = os.path.getmtime(auth_log)
        if (time.time() - mtime) > 86400 * 7: # Stale for >7 days
            use_journal = True

    if use_journal:
        try:
            _tail_journal(batch_size, flush_interval, cfg)
        except Exception as e:
            logger.error("Journal tailing failed: %s. Falling back to file.", e)
            _tail(auth_log, batch_size, flush_interval, cfg)
    else:
        _tail(auth_log, batch_size, flush_interval, cfg)


if __name__ == "__main__":
    from datetime import datetime
    main()
