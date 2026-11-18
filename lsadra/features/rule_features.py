"""
Time-windowed features the detection rules read.

``build_features`` (V3) computes the nine model features. The rules need more:
short and long authentication windows, per-source port and byte counts, a
cross-source flag, and per-event endpoint and persistence signals. This module
adds them to a frame that already holds the V3 columns, in one pass over the
events sorted by time.

Windows are real sliding time windows per key (source address, device,
destination). They only see what is in the frame, so the live path passes the
last ``RULE_LOOKBACK_MINUTES`` of stored events for the device as context rows
(see ``DetectionOrchestrator.run_for_new_events``); without that, an attack
split across detection runs would never cross a threshold.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict, deque
from datetime import timedelta
from typing import Any, Deque, Dict, Hashable, List, Tuple

import pandas as pd

from lsadra.detection.event_types import EVENT_TYPES, OTHER, canonical_event_type

#: Longest window any rule reads; the live path loads this much context.
RULE_LOOKBACK_MINUTES = 30

RULE_FEATURE_COLS: List[str] = [
    "canonical_event_type",
    "event_source",
    "failed_logins_last_5min",
    "login_attempts_last_5min",
    "login_attempt_velocity",
    "unique_dst_ports_10min",
    "bytes_out_to_dest_30min",
    "dest_ip",
    "dest_is_global",
    "cross_source_activity",
    "known_lolbin",
    "suspicious_cmdline",
    "encoded_command",
    "unusual_parent",
    "artifact_path",
    "artifact_in_user_writable_dir",
    "artifact_in_hidden_dir",
    "windows_artifact",
    "registry_autostart_key",
    "registry_service_key",
]

# ── endpoint signals (shared with the endpoint parser) ─────────────────────

KNOWN_LOLBINS = {
    "certutil", "mshta", "wscript", "cscript", "regsvr32",
    "rundll32", "msiexec", "installutil", "regasm", "regsvcs",
}

SUSPICIOUS_PARENTS: Dict[str, set] = {
    "winword.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "excel.exe":    {"cmd.exe", "powershell.exe", "wscript.exe"},
    "outlook.exe":  {"cmd.exe", "powershell.exe"},
    "iexplore.exe": {"cmd.exe", "powershell.exe"},
    "msedge.exe":   {"cmd.exe", "powershell.exe"},
    "chrome.exe":   {"cmd.exe", "powershell.exe"},
}

_SUSPICIOUS_CMDLINE_RE = re.compile(
    "|".join([
        r"frombase64string",                            # inline base64 decode
        r"(?:wget|curl|invoke-webrequest|iwr)\s+http",  # download cradle
        r"\\temp\\.*\.(?:exe|ps1|bat|vbs)",             # execution from temp
        r"/tmp/.*\.(?:sh|py|pl|elf)",                   # Linux /tmp execution
        r"certutil.*-(?:decode|urlcache)",              # certutil abuse
    ]),
    re.IGNORECASE,
)
_ENCODED_RE = re.compile(r"\s-(?:e|en|enc|encodedcommand|ec)\s", re.IGNORECASE)

# Directories any user can write to: binaries launched from here as a service
# or task are a classic persistence tell.
_USER_WRITABLE_RE = re.compile(
    r"(?:\\windows\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\[^\\]+\.exe"
    r"|\\temp\\|^/tmp/|^/var/tmp/|^/dev/shm/|/\.cache/)",
    re.IGNORECASE,
)
_HIDDEN_DIR_RE = re.compile(r"(?:^|/)\.[^/.][^/]*(?:/|$)")
_AUTOSTART_KEY_RE = re.compile(
    r"\\(?:software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\(?:run|runonce)"
    r"|software\\microsoft\\windows nt\\currentversion\\winlogon)(?:\\|$)",
    re.IGNORECASE,
)
_SERVICE_KEY_RE = re.compile(r"\\system\\currentcontrolset\\services\\", re.IGNORECASE)


def _attrs(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def _first(attrs: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = attrs.get(key)
        if value not in (None, ""):
            return value
    return None


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _basename(path: Any) -> str:
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _is_global(ip: Any) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


def endpoint_signals(event_type: str, attrs: Dict[str, Any]) -> Dict[str, Any]:
    """Per-event process, persistence and file signals from ``attributes``."""
    process = _first(attrs, "process_name", "binary", "process_path", "image", "service") or ""
    parent = _first(attrs, "parent_process", "parent_image") or ""
    cmdline = str(_first(attrs, "cmdline", "command_line", "command", "task_command") or "")
    proc_base = _basename(process)
    lolbin = attrs.get("known_lolbin")
    if lolbin is None:
        lolbin = proc_base.removesuffix(".exe") in KNOWN_LOLBINS
    suspicious = attrs.get("suspicious_cmdline")
    if suspicious is None:
        suspicious = bool(cmdline and _SUSPICIOUS_CMDLINE_RE.search(cmdline))
    encoded = _num(attrs.get("encoded_command_len")) > 0 or bool(
        cmdline and proc_base.startswith(("powershell", "pwsh")) and _ENCODED_RE.search(cmdline + " ")
    )
    unusual_parent = attrs.get("unusual_parent")
    if unusual_parent is None:
        unusual_parent = proc_base in SUSPICIOUS_PARENTS.get(_basename(parent), set())

    artifact = str(_first(
        attrs, "image_path", "task_command", "new_value", "dropped_path",
        "staging_dir", "archive_path", "target_path", "file_path", "path",
    ) or "")
    registry_key = str(attrs.get("registry_key") or "")
    return {
        "known_lolbin": int(bool(lolbin)),
        "suspicious_cmdline": int(bool(suspicious)),
        "encoded_command": int(bool(encoded)),
        "unusual_parent": int(bool(unusual_parent)),
        "artifact_path": artifact[:512],
        "artifact_in_user_writable_dir": int(bool(artifact and _USER_WRITABLE_RE.search(artifact))),
        "artifact_in_hidden_dir": int(bool(
            artifact and artifact.startswith("/") and _HIDDEN_DIR_RE.search(artifact)
        )),
        "windows_artifact": int("\\" in artifact or artifact.lower().endswith(".exe")
                                or bool(registry_key)),
        "registry_autostart_key": int(bool(registry_key and _AUTOSTART_KEY_RE.search(registry_key))),
        "registry_service_key": int(bool(registry_key and _SERVICE_KEY_RE.search(registry_key))),
    }


# ── sliding windows ────────────────────────────────────────────────────────

class _CountWindow:
    """Count of events per key within a trailing time window."""

    def __init__(self, minutes: int) -> None:
        self.span = timedelta(minutes=minutes)
        self.q: Dict[Hashable, Deque[Tuple[Any, float]]] = defaultdict(deque)
        self.total: Dict[Hashable, float] = defaultdict(float)

    def add(self, key: Hashable, ts: Any, value: float = 1.0) -> float:
        q = self.q[key]
        q.append((ts, value))
        self.total[key] += value
        while q and q[0][0] < ts - self.span:
            self.total[key] -= q.popleft()[1]
        return self.total[key]

    def peek(self, key: Hashable, ts: Any) -> float:
        q = self.q[key]
        while q and q[0][0] < ts - self.span:
            self.total[key] -= q.popleft()[1]
        return self.total[key] if q else 0.0


class _DistinctWindow:
    """Number of distinct values per key within a trailing time window."""

    def __init__(self, minutes: int) -> None:
        self.span = timedelta(minutes=minutes)
        self.q: Dict[Hashable, Deque[Tuple[Any, Hashable]]] = defaultdict(deque)
        self.counts: Dict[Hashable, Counter] = defaultdict(Counter)

    def add(self, key: Hashable, ts: Any, value: Hashable) -> int:
        q, counts = self.q[key], self.counts[key]
        q.append((ts, value))
        counts[value] += 1
        while q and q[0][0] < ts - self.span:
            _, old = q.popleft()
            counts[old] -= 1
            if counts[old] <= 0:
                del counts[old]
        return len(counts)


def _timestamps(df: pd.DataFrame) -> pd.Series:
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True, format="mixed")
    return ts.dt.tz_localize(None)


def build_rule_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return a copy of *df* with ``RULE_FEATURE_COLS`` added.

    *df* needs ``timestamp`` and ``event_type``; ``source_ip``, ``device_id``,
    ``attributes`` and the V3 columns are used when present. Rows keep their
    order and index.
    """
    out = df.copy()
    n = len(out)
    if n == 0:
        for col in RULE_FEATURE_COLS:
            out[col] = pd.Series(dtype=object)
        return out

    def col(name: str, default: Any = None) -> List[Any]:
        return out[name].tolist() if name in out.columns else [default] * n

    ts = _timestamps(out).tolist()
    event_types = [canonical_event_type(et) for et in col("event_type", "")]
    sources = [EVENT_TYPES[et].source for et in event_types]
    ips = [str(ip) if ip not in (None, "", 0) else "" for ip in col("source_ip")]
    devices = [str(d or "") for d in col("device_id", "")]
    attrs = [_attrs(a) for a in col("attributes")]

    features: List[Dict[str, Any]] = [{} for _ in range(n)]
    order = sorted(range(n), key=lambda i: (ts[i] is pd.NaT or ts[i] is None, ts[i] or 0, i))

    fail_5m = _CountWindow(5)
    tries_5m = _CountWindow(5)
    ports_10m = _DistinctWindow(10)
    bytes_30m = _CountWindow(RULE_LOOKBACK_MINUTES)
    families_15m = _DistinctWindow(15)

    for i in order:
        t = ts[i]
        et, src, ip, a = event_types[i], sources[i], ips[i], attrs[i]
        f = features[i]
        f["canonical_event_type"] = et
        f["event_source"] = src
        f.update(endpoint_signals(et, a))

        dest_ip = str(_first(a, "dest_ip", "dst_ip", "destination_ip") or "")
        f["dest_ip"] = dest_ip
        f["dest_is_global"] = int(_is_global(dest_ip)) if dest_ip else 0

        if pd.isna(t):
            for k in ("failed_logins_last_5min", "login_attempts_last_5min",
                      "unique_dst_ports_10min", "bytes_out_to_dest_30min"):
                f[k] = 0.0
            f["login_attempt_velocity"] = 0.0
            f["cross_source_activity"] = 0
            continue

        # Authentication bursts per source address
        if src == "auth" and et in ("auth_success", "auth_failure") and ip:
            tries = tries_5m.add(ip, t)
            fails = fail_5m.add(ip, t, 1.0 if et == "auth_failure" else 0.0)
        else:
            tries = tries_5m.peek(ip, t) if ip else 0.0
            fails = fail_5m.peek(ip, t) if ip else 0.0
        f["failed_logins_last_5min"] = fails
        f["login_attempts_last_5min"] = tries
        f["login_attempt_velocity"] = tries / 5.0

        # Network: distinct destination ports per source, bytes per destination
        if src == "network" and ip:
            port = _first(a, "dest_port", "dst_port", "destination_port")
            f["unique_dst_ports_10min"] = float(
                ports_10m.add(ip, t, str(port)) if port is not None else 0
            )
            out_bytes = _num(_first(a, "bytes_out", "bytes", "bytes_sent"))
            dkey = (devices[i], dest_ip or ip)
            f["bytes_out_to_dest_30min"] = bytes_30m.add(dkey, t, out_bytes)
        else:
            f["unique_dst_ports_10min"] = 0.0
            f["bytes_out_to_dest_30min"] = 0.0

        # Cross-source corroboration: same address in 2+ source families
        if ip and et != OTHER:
            f["cross_source_activity"] = int(families_15m.add(ip, t, src) >= 2)
        else:
            f["cross_source_activity"] = 0

    feat_df = pd.DataFrame(features, index=out.index)
    for c in RULE_FEATURE_COLS:
        out[c] = feat_df[c] if c in feat_df.columns else 0
    return out
