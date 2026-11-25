"""
LSADRA V4 — Endpoint telemetry parser.

Parses endpoint agent output in pipe-delimited or JSON format:
  timestamp|device_id|username|process_name|parent_process|cmdline|file_path|action

Enriches with:
  - suspicious_cmdline: base64, PowerShell encoded, wget/curl to external,
                        /tmp execution, cmd.exe→pwsh, whoami/net user
  - known_lolbin: certutil, mshta, wscript, cscript, regsvr32, rundll32,
                  msiexec, installutil, regasm, regsvcs
  - unusual_parent: known-bad child-parent combos (e.g., winword→cmd)

[V4 ENHANCEMENT — gap: multi-source ingestion]
[Capability: multi-source unified schema]
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from lsadra.ingestion.base_parser import BaseParser

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KNOWN_LOLBINS: Set[str] = {
    "certutil",
    "mshta",
    "wscript",
    "cscript",
    "regsvr32",
    "rundll32",
    "msiexec",
    "installutil",
    "regasm",
    "regsvcs",
}

SUSPICIOUS_PARENTS: Dict[str, Set[str]] = {
    "winword.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "excel.exe": {"cmd.exe", "powershell.exe", "wscript.exe"},
    "outlook.exe": {"cmd.exe", "powershell.exe"},
    "iexplore.exe": {"cmd.exe", "powershell.exe"},
    "msedge.exe": {"cmd.exe", "powershell.exe"},
    "chrome.exe": {"cmd.exe", "powershell.exe"},
}

VALID_ACTIONS: Set[str] = {
    "process_create",
    "file_write",
    "file_delete",
    "registry_write",
    "network_connect",
    "dll_load",
}

# Suspicious cmdline patterns (applied case-insensitively)
_SUSPICIOUS_PATTERNS: List[str] = [
    r"-(?:en|enc|encoded|encodedcommand)\s",  # PS encoded command
    r"frombase64string",  # inline base64 decode
    r"(?:wget|curl|invoke-webrequest|iwr)\s+http",  # download cradle
    r"\\temp\\.*\.(exe|ps1|bat|vbs)",  # execution from temp
    r"/tmp/.*\.(sh|py|pl|elf)",  # Linux /tmp execution
    r"cmd\.exe.*powershell|powershell.*cmd\.exe",  # cmd→powershell chain
    r"\bwhoami\b",  # recon
    r"\bnet\s+user\b",  # user enumeration
    r"\bnet\s+localgroup\b",  # group enumeration
    r"certutil.*-decode",  # certutil lolbin decode
]
_SUSPICIOUS_RE = re.compile("|".join(_SUSPICIOUS_PATTERNS), re.IGNORECASE)

# Pipe-delimited field order
_PIPE_FIELDS = [
    "timestamp",
    "device_id",
    "username",
    "process_name",
    "parent_process",
    "cmdline",
    "file_path",
    "action",
]


class EndpointParser(BaseParser):
    """
    Endpoint telemetry parser for V4 ingestion.

    Normalises pipe-delimited and JSON endpoint agent events into the
    unified V4 schema, enriching each event with process-level threat signals.

    [Capability: multi-source unified schema]
    [V4 ENHANCEMENT — gap: multi-source ingestion]
    """

    @property
    def source_type(self) -> str:
        """Returns the source type label for this parser."""
        return "endpoint"

    def can_parse(self, raw_line: str) -> bool:
        """
        Returns True if the line looks like an endpoint telemetry event.

        Args:
            raw_line: Raw log line to test.

        Returns:
            True if JSON or pipe-delimited endpoint format detected.
        """
        line = raw_line.strip()
        if not line:
            return False
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                return "action" in obj and "process_name" in obj
            except (ValueError, TypeError):
                return False
        parts = line.split("|")
        if len(parts) >= 7:
            action = parts[-1].strip()
            return action in VALID_ACTIONS
        return False

    def parse(self, raw_line: str, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Parse an endpoint telemetry line into the unified V4 event schema.

        Args:
            raw_line:  Raw endpoint event line (JSON or pipe-delimited).
            device_id: Originating device identifier.

        Returns:
            Unified event dict or None if unrecognised.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        if raw_line.startswith("{"):
            fields = self._parse_json(raw_line)
        else:
            fields = self._parse_pipe(raw_line)

        if not fields:
            return None

        ts = self._normalise_ts(fields.get("timestamp", ""))
        proc_name = fields.get("process_name", "").lower()
        parent = fields.get("parent_process", "").lower()
        cmdline = fields.get("cmdline", "")
        action = fields.get("action", "process_create")
        username = fields.get("username") or None
        file_path = fields.get("file_path", "")

        # Override device_id from the line if available and valid
        ev_device = fields.get("device_id") or device_id

        extra: Dict[str, Any] = {
            "process_name": proc_name,
            "parent_process": parent,
            "cmdline": cmdline[:512],
            "file_path": file_path,
            "action": action,
            "suspicious_cmdline": self._is_suspicious(cmdline),
            "known_lolbin": self._is_lolbin(proc_name),
            "unusual_parent": self._is_unusual_parent(parent, proc_name),
        }

        return {
            "timestamp": ts,
            "source_type": self.source_type,
            "source_ip": None,
            "dest_ip": None,
            "username": username,
            "event_type": action if action in VALID_ACTIONS else "process_create",
            "success": True,
            "raw": raw_line[:2048],
            "device_id": ev_device,
            "extra": extra,
        }

    # ------------------------------------------------------------------
    # Format parsers
    # ------------------------------------------------------------------

    def _parse_pipe(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a pipe-delimited endpoint event line into a field dict."""
        parts = line.split("|")
        if len(parts) < 7:
            return None
        result: Dict[str, str] = {}
        for i, key in enumerate(_PIPE_FIELDS):
            result[key] = parts[i].strip() if i < len(parts) else ""
        return result

    def _parse_json(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a JSON-format endpoint event line into a field dict."""
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                return None
            return {k: str(v) for k, v in obj.items()}
        except (ValueError, TypeError):
            return None

    # ------------------------------------------------------------------
    # Enrichment helpers
    # ------------------------------------------------------------------

    def _is_suspicious(self, cmdline: str) -> bool:
        """Return True if the command line contains known-suspicious patterns."""
        if not cmdline:
            return False
        return bool(_SUSPICIOUS_RE.search(cmdline))

    def _is_lolbin(self, proc_name: str) -> bool:
        """Return True if the process is a known Living-Off-The-Land Binary."""
        base = proc_name.split("\\")[-1].split("/")[-1].lower()
        base = base.replace(".exe", "")
        return base in KNOWN_LOLBINS

    def _is_unusual_parent(self, parent: str, child: str) -> bool:
        """Return True if the child process spawned from an unusual parent."""
        parent_base = parent.split("\\")[-1].split("/")[-1].lower()
        child_base = child.split("\\")[-1].split("/")[-1].lower()
        return child_base in SUSPICIOUS_PARENTS.get(parent_base, set())

    def _normalise_ts(self, ts_str: str) -> str:
        """Normalise timestamp to ISO 8601."""
        if not ts_str:
            return datetime.utcnow().isoformat()
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(ts_str.strip(), fmt).isoformat()
            except ValueError:
                continue
        return datetime.utcnow().isoformat()
