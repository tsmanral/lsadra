"""
LSADRA V4 — Syslog parser (RFC 3164 and RFC 5424).

Detects security-relevant syslog events beyond SSH:
  - sudo privilege escalation
  - cron job execution (persistence signal)
  - service start/stop
  - kernel module loading (rootkit indicator)
  - network interface events

[V4 ENHANCEMENT — gap: multi-source ingestion]
[Capability: multi-source unified schema]
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from lsadra.ingestion.base_parser import BaseParser

# ---------------------------------------------------------------------------
# Syslog header patterns
# ---------------------------------------------------------------------------

# RFC 3164: "Jan  5 12:34:56 hostname process[pid]: message"
_RFC3164_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<process>[A-Za-z0-9_./-]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

# RFC 5424: "<priority>1 timestamp hostname app pid msgid structured-data message"
_RFC5424_RE = re.compile(
    r"^<\d+>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+\S+\s+\S+\s*(?P<message>.*)$"
)

# Sub-patterns for message classification
_SUDO_RE      = re.compile(r"sudo.*COMMAND=(.*)")
_CRON_RE      = re.compile(r"(crond?|CRON)\s*\[.*\].*CMD\s+\((.*)\)")
_SERVICE_RE   = re.compile(r"(systemd|service)\[.*\]:\s+(Starting|Started|Stopping|Stopped)\s+(.*)")
_KERNEL_RE    = re.compile(r"kernel\s*:.*(\bmodule\b|\binsmod\b|\brmmod\b|\bModuleCore\b)")
_NETIF_RE     = re.compile(r"kernel\s*:.*\b(eth\d+|ens\d+|wlan\d+|tun\d+)\s+(up|down|SLAVE|MASTER)")
_FAILED_SU_RE = re.compile(r"su\[.*\].*FAILED SU.*for\s+(\S+)")


class SyslogParser(BaseParser):
    """
    General syslog parser supporting RFC 3164 and RFC 5424.

    Extracts security signals: sudo, cron, service changes, kernel module
    loading, and network interface events.

    [Capability: multi-source unified schema]
    [V4 ENHANCEMENT — gap: multi-source ingestion]
    """

    @property
    def source_type(self) -> str:
        """Returns the source type label for this parser."""
        return "syslog"

    def can_parse(self, raw_line: str) -> bool:
        """
        Returns True if this line matches syslog format and is not SSH auth.

        [DESIGN CHOICE] Excludes pure SSH auth lines as they are handled by the
        existing LinuxSSHParser to avoid duplicates.

        Args:
            raw_line: Raw log line to test.

        Returns:
            True if this is a syslog (non-SSH) line.
        """
        line = raw_line.strip()
        if not line:
            return False
        # Check for syslog header pattern
        if not (_RFC3164_RE.match(line) or _RFC5424_RE.match(line)):
            return False
        # Don't steal pure SSH lines from LinuxSSHParser
        if "sshd[" in line and ("Accepted " in line or "Failed " in line):
            return False
        return True

    def parse(self, raw_line: str, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Parse a syslog line into the unified V4 event schema.

        Args:
            raw_line:  Raw syslog line (RFC 3164 or RFC 5424).
            device_id: Originating device identifier.

        Returns:
            Unified event dict or None if unrecognised.
        """
        raw_line = raw_line.strip()
        parsed = self._parse_header(raw_line)
        if parsed is None:
            return None

        ts, host, process, pid, message = parsed
        event_type, success, extra = self._classify_message(process, message)

        extra.update({
            "facility":       self._extract_facility(raw_line),
            "severity_level": self._extract_severity_level(raw_line),
            "process_name":   process,
            "pid":            pid,
            "host":           host,
        })

        return {
            "timestamp":   ts,
            "source_type": self.source_type,
            "source_ip":   None,
            "dest_ip":     None,
            "username":    extra.pop("username", None),
            "event_type":  event_type,
            "success":     success,
            "raw":         raw_line[:2048],
            "device_id":   device_id,
            "extra":       extra,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_header(
        self, line: str
    ) -> Optional[tuple]:
        """Parse syslog header fields from the raw line."""
        m3164 = _RFC3164_RE.match(line)
        if m3164:
            g = m3164.groupdict()
            try:
                ts = datetime.strptime(
                    f"{datetime.now().year} {g['month']} {g['day']} {g['time']}",
                    "%Y %b %d %H:%M:%S",
                ).isoformat()
            except ValueError:
                ts = datetime.utcnow().isoformat()
            return ts, g["host"], g.get("process", "unknown"), g.get("pid"), g["message"]

        m5424 = _RFC5424_RE.match(line)
        if m5424:
            g = m5424.groupdict()
            try:
                ts = datetime.fromisoformat(g["ts"].replace("Z", "+00:00")).isoformat()
            except ValueError:
                ts = datetime.utcnow().isoformat()
            return ts, g["host"], g.get("app", "unknown"), g.get("pid"), g["message"]

        return None

    def _classify_message(
        self, process: str, message: str
    ) -> tuple:
        """Classify syslog message into event_type, success, extra dict."""
        extra: Dict[str, Any] = {}

        sudo = _SUDO_RE.search(message)
        if sudo:
            extra["command"] = sudo.group(1).strip()
            extra["username"] = self._extract_sudo_user(message)
            return "privilege_escalation", True, extra

        cron = _CRON_RE.search(message)
        if cron:
            extra["cron_user"] = cron.group(2)
            extra["command"] = cron.group(2)
            return "cron_modified", True, extra

        svc = _SERVICE_RE.search(message)
        if svc:
            action = svc.group(2).lower()
            extra["service_name"] = svc.group(3).strip()
            success = action in ("started", "starting")
            return "service_change", success, extra

        kern = _KERNEL_RE.search(message)
        if kern:
            extra["kernel_event"] = message[:200]
            return "kernel_module_load", True, extra

        netif = _NETIF_RE.search(message)
        if netif:
            extra["interface"] = netif.group(1)
            extra["state"] = netif.group(2)
            return "network_interface_change", True, extra

        failed_su = _FAILED_SU_RE.search(message)
        if failed_su:
            extra["username"] = failed_su.group(1)
            return "login_attempt", False, extra

        return "syslog_event", True, {"message_snippet": message[:200]}

    def _extract_sudo_user(self, message: str) -> Optional[str]:
        """Extract the username from a sudo message."""
        m = re.search(r"^(\S+)\s*:", message)
        return m.group(1) if m else None

    def _extract_facility(self, line: str) -> Optional[int]:
        """Extract syslog facility code from RFC 5424 priority."""
        m = re.match(r"^<(\d+)>", line)
        if m:
            priority = int(m.group(1))
            return priority >> 3
        return None

    def _extract_severity_level(self, line: str) -> Optional[int]:
        """Extract syslog severity from RFC 5424 priority."""
        m = re.match(r"^<(\d+)>", line)
        if m:
            priority = int(m.group(1))
            return priority & 0x07
        return None
