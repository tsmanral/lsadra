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
# Patterns with several unbounded ".*" gaps backtrack super-linearly on long,
# attacker-shaped lines, so sudo, cron and failed-su lines are matched with
# string searches plus single-gap patterns instead (see _match_* below).
_CRON_PREFIX_RE = re.compile(r"(?:crond?|CRON)\s*\[")
_CRON_CMD_RE  = re.compile(r"CMD\s+\(")
_SERVICE_RE   = re.compile(r"(systemd|service)\[.*\]:\s+(Starting|Started|Stopping|Stopped)\s+(.*)")
_KERNEL_RE    = re.compile(r"kernel\s*:.*(\bmodule\b|\binsmod\b|\brmmod\b|\bModuleCore\b)")
_NETIF_RE     = re.compile(r"kernel\s*:.*\b(eth\d+|ens\d+|wlan\d+|tun\d+)\s+(up|down|SLAVE|MASTER)")
_FOR_USER_RE  = re.compile(r"for\s+(\S+)")


def _match_sudo(message: str) -> Optional[str]:
    """Command of a sudo line ("sudo ... COMMAND=<cmd>"), else None."""
    start = message.find("sudo")
    if start < 0:
        return None
    at = message.rfind("COMMAND=")
    if at < start + len("sudo"):
        return None
    return message[at + len("COMMAND="):]


def _match_cron(message: str) -> Optional[str]:
    """Command of a cron line ("CRON[pid] ... CMD (<cmd>)"), else None."""
    prefix = _CRON_PREFIX_RE.search(message)
    if not prefix:
        return None
    close = message.find("]", prefix.end())
    if close < 0:
        return None
    end = message.rfind(")")
    cmd = None
    for found in _CRON_CMD_RE.finditer(message, close + 1):
        if found.end() > end:
            break
        cmd = found  # the last "CMD (" that still has a ")" after it wins
    if cmd is None:
        return None
    return message[cmd.end():end]


def _match_failed_su(message: str) -> Optional[str]:
    """Target user of a failed su ("su[pid] ... FAILED SU ... for <user>")."""
    start = message.find("su[")
    if start < 0:
        return None
    close = message.find("]", start + 3)
    if close < 0:
        return None
    failed = message.find("FAILED SU", close + 1)
    if failed < 0:
        return None
    lo = failed + len("FAILED SU")
    at = len(message)
    while True:  # the last "for <user>" wins, as with a greedy match
        at = message.rfind("for", lo, at + 2)
        if at < 0:
            return None
        user = _FOR_USER_RE.match(message, at)
        if user:
            return user.group(1)


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

        sudo_cmd = _match_sudo(message)
        if sudo_cmd is not None:
            extra["command"] = sudo_cmd.strip()
            extra["username"] = self._extract_sudo_user(message)
            return "privilege_escalation", True, extra

        cron_cmd = _match_cron(message)
        if cron_cmd is not None:
            extra["cron_user"] = cron_cmd
            extra["command"] = cron_cmd
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

        failed_su_user = _match_failed_su(message)
        if failed_su_user is not None:
            extra["username"] = failed_su_user
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
