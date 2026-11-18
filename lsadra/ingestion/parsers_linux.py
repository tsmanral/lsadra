"""
LSADRA V2 — Linux SSH / auth.log parser.

Converts raw syslog lines from ``/var/log/auth.log`` into ``NormalizedEvent``
dictionaries suitable for storage and detection.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

# Standard syslog pattern:
# Mar 20 14:55:02 myhost sshd[12345]: Accepted publickey for user from 1.2.3.4 port 55555 ssh2
_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[A-Za-z_.-]+)\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)

# SSH auth sub-patterns
_AUTH_RE = re.compile(
    r"(Failed|Accepted)\s+(password|publickey)\s+(?:for invalid user\s+)?"
    r"(?:for\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
_SESSION_RE = re.compile(r"session (opened|closed) for user\s+(\S+)")
# Anchored at the start of the message, and the user part cannot contain ':'
# or whitespace, so matching is linear in the line length. (An unanchored
# "(\S+)\s*:\s*.*COMMAND=" backtracks super-linearly on long lines.)
_SUDO_RE = re.compile(r"\s*([^\s:]+)\s*:.*?COMMAND=(.*)")


class LinuxSSHParser:
    """Parse Linux syslog SSH and sudo authentication events."""

    @staticmethod
    def parse(
        raw_line: str,
        device_id: Optional[str] = None,
        user_id: Optional[str] = None,
        year: int = datetime.now().year,
    ) -> Optional[Dict[str, Any]]:
        """
        Parse a single syslog line into a normalized event dict.

        Args:
            raw_line: Raw text line from auth.log.
            device_id: The registered device that produced this line.
            user_id: Owner of the device (propagated from devices table).
            year: Year to attach (syslog omits it).

        Returns:
            Normalized event dict, or *None* if the line is not parseable.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        m = _SYSLOG_RE.match(raw_line)
        if not m:
            return None

        g = m.groupdict()

        # Parse timestamp
        try:
            ts = datetime.strptime(
                f"{year} {g['month']} {g['day']} {g['time']}", "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            return None

        event: Dict[str, Any] = {
            "timestamp": ts.isoformat(),
            "host": g["host"],
            "device_id": device_id,
            "user_id": user_id,
            "effective_username": None,
            "source_ip": None,
            "event_type": "unknown",
            "raw_message": g["message"],
            "attributes": {"process": g["process"], "pid": int(g["pid"])},
        }

        msg = g["message"]

        # SSH auth success / failure
        auth = _AUTH_RE.search(msg)
        if auth:
            status = auth.group(1).lower()
            method = auth.group(2).lower()
            event["event_type"] = f"ssh_{status}_{method}"
            event["effective_username"] = auth.group(3)
            event["source_ip"] = auth.group(4)
            event["attributes"]["src_port"] = int(auth.group(5))
            return event

        # Session open / close
        sess = _SESSION_RE.search(msg)
        if sess:
            event["event_type"] = f"session_{sess.group(1)}"
            event["effective_username"] = sess.group(2)
            return event

        # Sudo command execution
        sudo = _SUDO_RE.match(msg)
        if sudo:
            event["event_type"] = "sudo_command"
            event["effective_username"] = sudo.group(1)
            event["attributes"]["command"] = sudo.group(2).strip()
            return event

        return event  # return as 'unknown' type
