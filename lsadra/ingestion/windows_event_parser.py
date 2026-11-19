"""
LSADRA V4 — Windows Security Event Log parser.

Extends V3's WindowsLogonParser skeleton to cover additional high-value
Event IDs required for V4 threat detection:

  4624  — Successful logon
  4625  — Failed logon
  4648  — Logon using explicit credentials
  4672  — Special privileges assigned to new session
  4688  — New process created
  4698  — Scheduled task created (persistence)
  4720  — User account created
  7045  — New service installed
  1102  — Security event log cleared

Supports XML-format and pipe-delimited flat log lines.
Outputs unified V4 event schema.

[V4 ENHANCEMENT — gap: multi-source ingestion]
[Capability: multi-source unified schema]
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Optional

from lsadra.ingestion.base_parser import BaseParser

# ---------------------------------------------------------------------------
# Event ID → (canonical event_type, success). ATT&CK techniques are assigned by
# detection rules (lsadra/detection/attack_map.py), never by a parser: a logon
# or a new service is not evidence of a technique on its own.
_EVENT_MAP: Dict[str, tuple] = {
    "4624": ("auth_success",          True),
    "4625": ("auth_failure",          False),
    "4648": ("auth_success",          True),
    "4672": ("privileged_logon",      True),
    "4688": ("process_exec",          True),
    "4698": ("scheduled_task_create", True),
    "4720": ("account_create",        True),
    "7045": ("service_install",       True),
    "1102": ("log_cleared",           True),
}

# Pipe-delimited flat format: EventID|timestamp|username|source_ip|...
_PIPE_RE = re.compile(
    r"^(?P<event_id>\d{4})\|(?P<ts>[^|]+)\|(?P<user>[^|]*)\|"
    r"(?P<ip>[^|]*)\|(?P<dest>[^|]*)\|?(?P<extra>.*)$"
)

_LOGON_TYPES: Dict[str, str] = {
    "2": "Interactive", "3": "Network", "4": "Batch",
    "5": "Service",     "7": "Unlock",  "8": "NetworkCleartext",
    "9": "NewCredentials", "10": "RemoteInteractive", "11": "CachedInteractive",
}


class WindowsEventParser(BaseParser):
    """
    Windows Security Event Log parser for V4 ingestion.

    Handles XML-format and pipe-delimited Windows event logs, normalising
    event data to the unified V4 schema for downstream ML and rule engines.

    [Capability: multi-source unified schema]
    [V4 ENHANCEMENT — gap: multi-source ingestion]
    """

    SUPPORTED_EVENT_IDS = set(_EVENT_MAP.keys())

    @property
    def source_type(self) -> str:
        """Returns the source type label for this parser."""
        return "windows_event"

    def can_parse(self, raw_line: str) -> bool:
        """
        Returns True if the line looks like a Windows event log entry.

        Args:
            raw_line: A raw log line to inspect.

        Returns:
            True if XML or pipe-delimited Windows event format is detected.
        """
        line = raw_line.strip()
        if line.startswith("<Event") or ("<System>" in line and "<EventID>" in line):
            return True
        m = _PIPE_RE.match(line)
        if m and m.group("event_id") in self.SUPPORTED_EVENT_IDS:
            return True
        return False

    def parse(self, raw_line: str, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Parse a Windows event log line into the unified V4 event schema.

        Attempts XML parsing first, falls back to pipe-delimited parsing.

        Args:
            raw_line:  Raw Windows event log line or XML string.
            device_id: Originating device identifier.

        Returns:
            Unified event dict or None if not parseable.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        if raw_line.startswith("<"):
            return self._parse_xml(raw_line, device_id)
        return self._parse_pipe(raw_line, device_id)

    # ------------------------------------------------------------------
    # XML parser
    # ------------------------------------------------------------------

    def _parse_xml(self, xml_text: str, device_id: str) -> Optional[Dict[str, Any]]:
        """Parse an XML-format Windows Security Event."""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None

        ns = ""
        m = re.match(r"\{(.*?)\}", root.tag)
        if m:
            ns = m.group(1)

        def _find(path: str) -> Optional[str]:
            el = root.find(path, {"ns": ns} if ns else {})
            return el.text if el is not None else None

        sys_path = ".//ns:System" if ns else ".//System"
        event_id = _find(f"{sys_path}/ns:EventID") if ns else _find(".//System/EventID")

        if event_id not in self.SUPPORTED_EVENT_IDS:
            return None

        ts = self._extract_ts_xml(root, ns)
        computer = _find(f"{sys_path}/ns:Computer") if ns else _find(".//System/Computer")
        data_fields = self._extract_data_fields(root, ns)

        return self._build_event(event_id, ts, data_fields, computer, xml_text[:2048], device_id)

    def _extract_ts_xml(self, root: ET.Element, ns: str) -> str:
        """Extract and normalise the TimeCreated attribute from XML."""
        tag = "{%s}TimeCreated" % ns if ns else "TimeCreated"
        el = root.find(f".//{tag}")
        ts_raw = el.get("SystemTime", "") if el is not None else ""
        try:
            return datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return datetime.utcnow().isoformat()

    def _extract_data_fields(self, root: ET.Element, ns: str) -> Dict[str, str]:
        """Extract EventData Name→value pairs from the XML tree."""
        fields: Dict[str, str] = {}
        tag = "{%s}Data" % ns if ns else "Data"
        for el in root.iter(tag):
            name = el.get("Name", "")
            fields[name] = el.text or ""
        return fields

    # ------------------------------------------------------------------
    # Pipe-delimited parser
    # ------------------------------------------------------------------

    def _parse_pipe(self, line: str, device_id: str) -> Optional[Dict[str, Any]]:
        """Parse a pipe-delimited flat Windows event log line."""
        m = _PIPE_RE.match(line)
        if not m:
            return None
        event_id = m.group("event_id")
        if event_id not in self.SUPPORTED_EVENT_IDS:
            return None

        try:
            ts = datetime.fromisoformat(m.group("ts").replace("Z", "+00:00")).isoformat()
        except ValueError:
            ts = datetime.utcnow().isoformat()

        data_fields = {
            "TargetUserName": m.group("user"),
            "IpAddress":      m.group("ip"),
        }
        return self._build_event(event_id, ts, data_fields, None, line, device_id)

    # ------------------------------------------------------------------
    # Shared builder
    # ------------------------------------------------------------------

    def _build_event(
        self,
        event_id: str,
        ts: str,
        data_fields: Dict[str, str],
        computer: Optional[str],
        raw: str,
        device_id: str,
    ) -> Dict[str, Any]:
        """Assemble the final unified event dict from extracted components."""
        event_type, success = _EVENT_MAP[event_id]
        username    = data_fields.get("TargetUserName") or data_fields.get("SubjectUserName") or None
        source_ip   = data_fields.get("IpAddress") or None
        if source_ip in ("-", "::1", "127.0.0.1"):
            source_ip = None

        extra: Dict[str, Any] = {
            "event_id":    event_id,
            "logon_type":  _LOGON_TYPES.get(data_fields.get("LogonType", ""), ""),
            "domain":      data_fields.get("TargetDomainName", ""),
            "computer":    computer or "",
            "process_name": data_fields.get("NewProcessName", ""),
            "task_name":   data_fields.get("TaskName", ""),
            "service_name": data_fields.get("ServiceName", ""),
        }

        return {
            "timestamp":   ts,
            "source_type": self.source_type,
            "source_ip":   source_ip,
            "dest_ip":     None,
            "username":    username,
            "event_type":  event_type,
            "success":     success,
            "raw":         raw,
            "device_id":   device_id,
            "extra":       extra,
        }
