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
# The core takes at most this many events per batch (MAX_EVENTS_PER_BATCH); a
# bigger batch is a 422 and would be dropped whole.
MAX_BATCH_SIZE = 100
# Events held in memory while a send is pending. The stopgap agent has no disk
# spool, so past this cap the oldest events are dropped rather than growing
# without bound.
MAX_BUFFERED_EVENTS = 1000

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

    if "log_paths" in loaded:
        loaded["log_paths"] = _parse_path_list(loaded["log_paths"])
    cfg.update(loaded)
    return cfg


def _parse_path_list(value: Any) -> List[str]:
    """Accept `[a, b]`, `a, b` or a single path; the loader only sees one line."""
    if isinstance(value, list):
        items = value
    else:
        items = str(value).strip().strip("[]").split(",")
    return [p.strip().strip("'\"") for p in items if p.strip().strip("'\"")]


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
            delay = _retry_after(exc) if exc.code in (429, 503) else None
            if delay is None:
                delay = backoff
                backoff = min(backoff * 2, MAX_BACKOFF)
            logger.warning("Send failed (%s), retrying in %ds ...", exc, delay)
            time.sleep(delay)
        except Exception as exc:
            logger.warning("Send failed (%s), retrying in %ds ...", exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF)


def _retry_after(exc: urllib.error.HTTPError) -> Optional[int]:
    """Seconds from a Retry-After header (delta form), clamped to MAX_BACKOFF."""
    try:
        value = int((exc.headers or {}).get("Retry-After", ""))
    except (TypeError, ValueError):
        return None
    return min(max(value, 1), MAX_BACKOFF)


class _Batcher:
    """Buffer parsed events and flush them in contract-sized batches.

    A flush always empties what it sent: `_send_batch` only returns once the
    batch was accepted or rejected for good (422), and a rejected batch can
    never succeed on resend. Keeping it, as the journal loop used to, re-sent
    the same invalid batch after every new line and never shipped another event.
    """

    def __init__(self, batch_size: int, flush_interval: float, cfg: Dict[str, Any]):
        self.batch_size = max(1, min(int(batch_size), MAX_BATCH_SIZE))
        self.flush_interval = flush_interval
        self.cfg = cfg
        self.buffer: List[Dict[str, Any]] = []
        self.last_flush = time.time()
        self.dropped = 0

    def add(self, ev: Dict[str, Any]) -> None:
        self.buffer.append(ev)
        if len(self.buffer) > MAX_BUFFERED_EVENTS:
            overflow = len(self.buffer) - MAX_BUFFERED_EVENTS
            del self.buffer[:overflow]
            self.dropped += overflow
            logger.warning("Event buffer full, dropped %d oldest event(s) (%d total)",
                           overflow, self.dropped)

    def maybe_flush(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        if len(self.buffer) >= self.batch_size or (
            self.buffer and now - self.last_flush >= self.flush_interval
        ):
            self.flush()
            self.last_flush = now

    def flush(self) -> None:
        while self.buffer:
            batch = self.buffer[: self.batch_size]
            del self.buffer[: len(batch)]
            _send_batch(batch, self.cfg["server_url"], self.cfg["collector_endpoint"],
                        self.cfg["device_id"], self.cfg["api_key"])


# ── File tailer ───────────────────────────────────────────────────────────

def _tail(path: str, batch_size: int, flush_interval: float, cfg: Dict[str, Any]):
    logger.info("Tailing %s  (batch=%d, flush=%ds)", path, batch_size, flush_interval)
    batcher = _Batcher(batch_size, flush_interval, cfg)

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
                    batcher.add(ev)

            batcher.maybe_flush()

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

    batcher = _Batcher(batch_size, flush_interval, cfg)

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
                batcher.add(ev)

            batcher.maybe_flush()
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

    log_paths = _parse_path_list(cfg.get("log_paths") or [])
    configured = "log_paths" in cfg and cfg["log_paths"] != DEFAULT_CONFIG["log_paths"]
    existing = [p for p in log_paths if os.path.exists(p)]
    for p in log_paths:
        if p not in existing:
            logger.warning("Configured log path %s does not exist, skipping it.", p)

    if configured and existing:
        # The operator named the files to watch: tail exactly those.
        _tail_paths(existing, batch_size, flush_interval, cfg)
        return

    import shutil
    use_journal = False
    if shutil.which("journalctl") or not existing:
        use_journal = True
    elif all((time.time() - os.path.getmtime(p)) > 86400 * 7 for p in existing):
        use_journal = True  # every file is stale for >7 days

    if use_journal:
        try:
            _tail_journal(batch_size, flush_interval, cfg)
        except Exception as e:
            logger.error("Journal tailing failed: %s. Falling back to file.", e)
            _tail_paths(existing, batch_size, flush_interval, cfg)
    else:
        _tail_paths(existing, batch_size, flush_interval, cfg)


def _tail_paths(paths: List[str], batch_size: int, flush_interval: float, cfg: Dict[str, Any]):
    """Tail each path; one thread per extra file, the first on this thread."""
    if not paths:
        logger.error("No readable log path to tail.")
        return
    import threading
    for p in paths[1:]:
        threading.Thread(target=_tail, args=(p, batch_size, flush_interval, cfg),
                         name=f"tail:{p}", daemon=True).start()
    _tail(paths[0], batch_size, flush_interval, cfg)

if __name__ == "__main__":
    from datetime import datetime
    main()
