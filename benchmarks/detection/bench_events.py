"""
Event sources for the detection bench.

Every source yields :class:`BenchEvent` objects in the v1 contract shape
(``docs/contracts/event-schema.v1.json``) plus a ground-truth label, so the
replay in ``run_detection_bench.py`` can feed them to the unmodified detection
pipeline the same way ``POST /api/events/batch`` stores them.

Sources:

* :func:`generate_benign` - seeded synthetic background traffic (the negative
  class). Hosts ``bench-host-NN``, users ``*.demo``, RFC 5737 addresses only.
* :func:`load_demo_corpus` - the labelled corpus in ``demo/corpus/``.
* :func:`load_windows_dataset` - Windows Security/System/Sysmon events from the
  pinned public subsets in ``datasets.json`` (XML lines, Splunk WinEventLog
  text, or EVTX). These are read from the local cache only and never written
  back into the repository.
"""

from __future__ import annotations

import json
import random
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_CORPUS_DIR = REPO_ROOT / "demo" / "corpus"

# The bench calendar: day 0 is a Monday, so weekends fall on days 5-6, 12-13, ...
BASE_DATE = datetime(2026, 1, 5, tzinfo=timezone.utc)

# Contract limits (docs/contracts/event-schema.v1.json).
_MAX_HOST = 255
_MAX_USER = 128
_MAX_EVENT_TYPE = 64
_MAX_RAW = 4096


@dataclass
class BenchEvent:
    """One contract-shaped event plus its ground truth."""

    timestamp: datetime
    host: str
    event_type: str
    effective_username: Optional[str] = None
    source_ip: Optional[str] = None
    raw_message: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    # Ground truth. ``role`` is "negative", "positive" or "context" (context
    # events are replayed but excluded from every rate).
    role: str = "negative"
    technique: Optional[str] = None
    instance: Optional[str] = None
    source: str = "synthetic"

    def contract_fields(self) -> Dict[str, Any]:
        """The fields the ingestion API stores for this event."""
        return {
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds"),
            "host": self.host[:_MAX_HOST],
            "effective_username": (self.effective_username or None) and self.effective_username[:_MAX_USER],
            "source_ip": self.source_ip or None,
            "event_type": self.event_type[:_MAX_EVENT_TYPE],
            "raw_message": self.raw_message[:_MAX_RAW],
            "attributes": self.attributes,
        }


# ============================================================================
# Synthetic benign background
# ============================================================================

_LINUX_CMDS = [
    "ls -la", "systemctl status nginx", "tail -n 50 /var/log/app.log", "git pull",
    "df -h", "top -b -n 1", "journalctl -u app --since today", "vim config.yml",
]
_WIN_PROCS = [
    "C:\\Windows\\explorer.exe", "C:\\Program Files\\Office\\outlook.exe",
    "C:\\Program Files\\Browser\\browser.exe", "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\taskhostw.exe", "C:\\Program Files\\Teams\\teams.exe",
]


def _at(day: int, hour: float) -> datetime:
    return BASE_DATE + timedelta(days=day, seconds=int(hour * 3600))


def generate_benign(hosts: int, days: int, seed: int) -> List[BenchEvent]:
    """Seeded synthetic background traffic for ``hosts`` hosts over ``days`` days.

    Roughly 60 % Linux servers and 40 % Windows workstations. Each host has its
    own users and client addresses. The traffic includes the ordinary
    near-misses a real fleet has: password typos followed by a success, a
    nightly backup login, and an occasional on-call admin login at night.
    """
    rng = random.Random(seed)
    events: List[BenchEvent] = []
    for h in range(hosts):
        host = f"bench-host-{h + 1:02d}"
        is_linux = h % 5 < 3
        users = [f"u{h + 1:02d}{c}.demo" for c in "abcd"[: rng.randint(2, 4)]]
        user_ips = {u: f"192.0.2.{rng.randint(10, 200)}" for u in users}
        admin = f"ops-{h % 4 + 1}.demo"
        admin_ip = f"198.51.100.{rng.randint(100, 200)}"
        has_backup = rng.random() < 0.3
        for day in range(days):
            weekend = (BASE_DATE + timedelta(days=day)).weekday() >= 5
            if is_linux:
                events += _linux_day(rng, host, day, weekend, users, user_ips, admin, admin_ip, has_backup)
            else:
                events += _windows_day(rng, host, day, weekend, users, user_ips, admin, admin_ip)
    events.sort(key=lambda e: e.timestamp)
    return events


def _gt(event: BenchEvent) -> BenchEvent:
    event.attributes.setdefault("ground_truth", {"label": "benign", "scenario": "synthetic", "attack_technique": None})
    return event


def _login(rng: random.Random, host: str, ts: datetime, user: str, ip: str, linux: bool) -> List[BenchEvent]:
    out: List[BenchEvent] = []
    if rng.random() < 0.03:  # password typo, then success
        for k in range(rng.randint(1, 2)):
            out.append(_gt(BenchEvent(
                ts - timedelta(seconds=20 - 8 * k), host, "auth_failure", user, ip,
                f"Failed password for {user} from {ip}" if linux else f"Logon failure for {user}",
                {"service": "sshd" if linux else "winlogon"},
            )))
    out.append(_gt(BenchEvent(
        ts, host, "auth_success", user, ip,
        f"Accepted publickey for {user} from {ip}" if linux else f"Logon success for {user}",
        {"service": "sshd" if linux else "winlogon"},
    )))
    return out


def _linux_day(rng, host, day, weekend, users, user_ips, admin, admin_ip, has_backup) -> List[BenchEvent]:
    out: List[BenchEvent] = []
    n_logins = rng.randint(1, 3) if weekend else rng.randint(5, 12)
    for _ in range(n_logins):
        user = rng.choice(users)
        ts = _at(day, rng.uniform(8.0, 18.0))
        out += _login(rng, host, ts, user, user_ips[user], True)
        for k in range(rng.randint(2, 6)):
            out.append(_gt(BenchEvent(
                ts + timedelta(seconds=30 + 40 * k + rng.randint(0, 30)), host, "process_exec", user, None,
                rng.choice(_LINUX_CMDS), {"service": "bash"},
            )))
    for hour in range(24):
        out.append(_gt(BenchEvent(_at(day, hour + rng.uniform(0, 0.02)), host, "cron_job", "root", None,
                                  "CRON[1]: (root) CMD (run-parts /etc/cron.hourly)", {"service": "cron"})))
    out.append(_gt(BenchEvent(_at(day, 6.5 + rng.uniform(0, 0.2)), host, "package_update", "root", None,
                              "apt: upgraded 3 packages", {"service": "apt"})))
    for _ in range(rng.randint(10, 25)):
        out.append(_gt(BenchEvent(_at(day, rng.uniform(0, 24)), host, "network_flow", None, "192.0.2.250",
                                  "outbound tcp 443 to mirror", {"dst_port": 443, "bytes_out": rng.randint(500, 90000)})))
    if has_backup:
        out += _login(rng, host, _at(day, 1.0 + rng.uniform(0, 0.4)), "svc-backup.demo", "192.0.2.61", True)
    if rng.random() < 0.03:  # on-call admin at night
        out += _login(rng, host, _at(day, rng.choice([0.5, 2.5, 23.2]) + rng.uniform(0, 0.5)), admin, admin_ip, True)
    return out


def _windows_day(rng, host, day, weekend, users, user_ips, admin, admin_ip) -> List[BenchEvent]:
    out: List[BenchEvent] = []
    if weekend and rng.random() < 0.8:
        active = []
    else:
        active = [users[0]] + ([u for u in users[1:] if rng.random() < 0.3])
    out.append(_gt(BenchEvent(_at(day, 7.5 + rng.uniform(0, 0.5)), host, "service_start", "SYSTEM", None,
                              "Service Control Manager: service entered the running state", {"service": "scm"})))
    for user in active:
        start = rng.uniform(8.0, 10.0)
        out += _login(rng, host, _at(day, start), user, user_ips[user], False)
        for _ in range(rng.randint(1, 3)):  # unlocks after breaks
            out += _login(rng, host, _at(day, rng.uniform(start + 0.5, 17.5)), user, user_ips[user], False)
        for _ in range(rng.randint(15, 40)):
            out.append(_gt(BenchEvent(_at(day, rng.uniform(start, 18.0)), host, "process_exec", user, None,
                                      rng.choice(_WIN_PROCS), {"service": "process"})))
        for _ in range(rng.randint(20, 50)):
            out.append(_gt(BenchEvent(_at(day, rng.uniform(start, 18.0)), host, "network_flow", user, "192.0.2.251",
                                      "outbound tcp 443", {"dst_port": 443, "bytes_out": rng.randint(500, 200000)})))
        for _ in range(rng.randint(0, 5)):
            out.append(_gt(BenchEvent(_at(day, rng.uniform(start, 18.0)), host, "registry_set", user, None,
                                      "HKCU\\Software\\App\\Settings", {"service": "registry"})))
    for _ in range(rng.randint(2, 6)):  # background services, any hour
        out.append(_gt(BenchEvent(_at(day, rng.uniform(0, 24)), host, "process_exec", "SYSTEM", None,
                                  "C:\\Windows\\System32\\svchost.exe -k netsvcs", {"service": "process"})))
    if rng.random() < 0.02:  # on-call admin RDP at night
        out += _login(rng, host, _at(day, rng.choice([0.5, 23.2]) + rng.uniform(0, 0.5)), admin, admin_ip, False)
    return out


# ============================================================================
# Demo corpus
# ============================================================================

def load_demo_corpus(skip: Iterable[str] = ("injection_attempts",)) -> Dict[str, List[BenchEvent]]:
    """Load ``demo/corpus/*.jsonl`` keyed by scenario.

    ``injection_attempts`` is a security fixture for the narrative engine, not
    a detection scenario, so it is skipped by default. Malicious and suspicious
    events with an ATT&CK technique are positives; benign events are negatives;
    anything else is context.
    """
    out: Dict[str, List[BenchEvent]] = {}
    for path in sorted(DEMO_CORPUS_DIR.glob("*.jsonl")):
        if path.stem in skip:
            continue
        events: List[BenchEvent] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            gt = raw.get("attributes", {}).get("ground_truth", {})
            label, tech = gt.get("label"), gt.get("attack_technique")
            if label == "benign":
                role = "negative"
            elif label in ("malicious", "suspicious") and tech:
                role = "positive"
            else:
                role = "context"
            events.append(BenchEvent(
                timestamp=datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00")),
                host=raw["host"],
                event_type=raw["event_type"],
                effective_username=raw.get("effective_username"),
                source_ip=raw.get("source_ip"),
                raw_message=raw.get("raw_message", ""),
                attributes=raw.get("attributes", {}),
                role=role,
                technique=tech if role == "positive" else None,
                instance=f"demo/{path.stem}/{tech}" if role == "positive" else None,
                source="demo",
            ))
        out[path.stem] = events
    return out


# ============================================================================
# Windows event adapters (public datasets)
# ============================================================================

# Channel-independent event id → contract event type. Ids missing here map to
# ``win_<id>``. Kerberos/NTLM ids are refined by their status code below.
_WIN_EVENT_TYPES = {
    ("security", "4624"): "auth_success",
    ("security", "4625"): "auth_failure",
    ("security", "4648"): "explicit_credential_logon",
    ("security", "4672"): "special_privileges_assigned",
    ("security", "4688"): "process_exec",
    ("security", "4689"): "process_exit",
    ("security", "4697"): "service_install",
    ("security", "4698"): "scheduled_task_create",
    ("security", "4699"): "scheduled_task_delete",
    ("security", "4720"): "account_create",
    ("security", "4728"): "group_member_add",
    ("security", "4732"): "group_member_add",
    ("security", "4756"): "group_member_add",
    ("security", "4634"): "logoff",
    ("security", "1102"): "audit_log_cleared",
    ("system", "7045"): "service_install",
    ("system", "7036"): "service_state_change",
    ("sysmon", "1"): "process_exec",
    ("sysmon", "3"): "network_flow",
    ("sysmon", "11"): "file_create",
    ("sysmon", "13"): "registry_set",
}
_KERBEROS_STATUS_IDS = {"4768", "4771", "4776"}


def _channel(provider: str, channel: str) -> str:
    p = f"{provider} {channel}".lower()
    if "sysmon" in p:
        return "sysmon"
    if "security" in p:
        return "security"
    return "system"


def _map_windows(
    event_id: str, provider: str, channel: str, data: Dict[str, str]
) -> str:
    ch = _channel(provider, channel)
    if event_id in _KERBEROS_STATUS_IDS:
        status = (data.get("Status") or data.get("FailureCode") or data.get("ErrorCode")
                  or data.get("Result Code") or data.get("Failure Code") or data.get("Error Code") or "0x0")
        return "auth_success" if status.strip().lower() in ("0x0", "0", "") else "auth_failure"
    if ch == "security" and event_id == "1102":
        return "audit_log_cleared"
    return _WIN_EVENT_TYPES.get((ch, event_id)) or _WIN_EVENT_TYPES.get(("security", event_id)) or f"win_{event_id}"


def _clean_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip()
    if value.startswith("::ffff:"):
        value = value[7:]
    if value in ("-", "::1", "127.0.0.1", "") or not re.match(r"^[0-9a-fA-F:.]+$", value):
        return None
    return value


def _pick_user(data: Dict[str, str]) -> Optional[str]:
    for key in ("TargetUserName", "Account Name", "User", "SubjectUserName", "AccountName"):
        v = data.get(key)
        if v and v not in ("-", "SYSTEM") and not v.endswith("$"):
            return v
    return data.get("TargetUserName") or data.get("SubjectUserName") or data.get("User")


def _build_windows_event(ts: datetime, event_id: str, provider: str, channel: str,
                         data: Dict[str, str]) -> BenchEvent:
    event_type = _map_windows(event_id, provider, channel, data)
    ip = _clean_ip(data.get("IpAddress") or data.get("Source Network Address")
                   or data.get("Client Address") or data.get("SourceIp"))
    return BenchEvent(
        timestamp=ts,
        host="",  # replaced by the bench host the instance is injected into
        event_type=event_type,
        effective_username=_pick_user(data),
        source_ip=ip,
        raw_message=f"{provider} event {event_id}",
        attributes={"event_id": event_id, "provider": provider[:128]},
    )


def _parse_event_xml(xml: str) -> Optional[BenchEvent]:
    xml = re.sub(r"\sxmlns(:\w+)?=(['\"]).*?\2", "", xml, count=1)
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    system = root.find("System")
    if system is None:
        return None
    eid = (system.findtext("EventID") or "").strip()
    prov_el = system.find("Provider")
    provider = prov_el.get("Name", "") if prov_el is not None else ""
    channel = system.findtext("Channel") or ""
    tc = system.find("TimeCreated")
    raw_ts = tc.get("SystemTime", "") if tc is not None else ""
    ts = _parse_iso(raw_ts)
    if ts is None:
        return None
    data: Dict[str, str] = {}
    ed = root.find("EventData")
    if ed is not None:
        for d in ed.findall("Data"):
            if d.get("Name"):
                data[d.get("Name")] = (d.text or "").strip()
    return _build_windows_event(ts, eid, provider, channel, data)


def _parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip().replace("Z", "+00:00")
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", value)
    if not m:
        return None
    frac = (m.group(2) or "")[:7]
    try:
        dt = datetime.fromisoformat(m.group(1).replace(" ", "T") + frac[:7] + (m.group(3) or "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iter_windows_xml_lines(text: str) -> Iterator[BenchEvent]:
    """One ``<Event>...</Event>`` per line (Splunk XmlWinEventLog exports)."""
    for chunk in re.findall(r"<Event[ >].*?</Event>", text, flags=re.S):
        ev = _parse_event_xml(chunk)
        if ev is not None:
            yield ev


_SPLUNK_HEADER = re.compile(r"^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M)\s*$", re.M)


def iter_splunk_wineventlog(text: str) -> Iterator[BenchEvent]:
    """Splunk classic WinEventLog text: a timestamp line, key=value lines, Message."""
    starts = [m.start() for m in _SPLUNK_HEADER.finditer(text)] + [len(text)]
    for a, b in zip(starts, starts[1:]):
        block = text[a:b]
        lines = block.splitlines()
        try:
            ts = datetime.strptime(lines[0].strip(), "%m/%d/%Y %I:%M:%S %p").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        kv: Dict[str, str] = {}
        data: Dict[str, str] = {}
        for line in lines[1:]:
            if "=" in line and not line.startswith(("\t", " ")) and ":" not in line.split("=", 1)[0]:
                k, v = line.split("=", 1)
                kv.setdefault(k.strip(), v.strip())
            elif ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if k and v and k not in data:
                    data[k] = v
        eid = kv.get("EventCode", "")
        if not eid:
            continue
        # The first "Account Name" in a 4624/4625 block is the subject; the
        # target account follows under "New Logon"/"Account For Which Logon Failed".
        names = re.findall(r"^\s*Account Name:\s*(\S.*)$", block, flags=re.M)
        targets = [n.strip() for n in names if n.strip() not in ("-",) and not n.strip().endswith("$")]
        if targets:
            data["Account Name"] = targets[-1]
        yield _build_windows_event(ts, eid, kv.get("SourceName", ""), kv.get("LogName", ""), data)


def iter_evtx(path: Path) -> Iterator[BenchEvent]:
    """EVTX via the optional ``evtx`` package (pip install evtx)."""
    try:
        import evtx  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("EVTX datasets need the 'evtx' package: pip install evtx") from exc
    parser = evtx.PyEvtxParser(str(path))
    for record in parser.records():
        ev = _parse_event_xml(record["data"])
        if ev is not None:
            yield ev


def load_windows_dataset(entry: Dict[str, Any], path: Path) -> List[BenchEvent]:
    """Parse one pinned dataset file and label its events."""
    fmt = entry["format"]
    if fmt == "evtx":
        events = list(iter_evtx(path))
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
        events = list(iter_windows_xml_lines(text) if fmt == "windows_xml" else iter_splunk_wineventlog(text))
    positives = set(entry["positive_event_types"])
    for ev in events:
        ev.source = entry["source"]
        if ev.event_type in positives:
            ev.role, ev.technique, ev.instance = "positive", entry["technique"], entry["id"]
        else:
            ev.role = "context"
        ev.attributes["ground_truth"] = {
            "label": "malicious" if ev.role == "positive" else "context",
            "scenario": entry["id"],
            "attack_technique": ev.technique,
        }
    events.sort(key=lambda e: e.timestamp)
    return events
