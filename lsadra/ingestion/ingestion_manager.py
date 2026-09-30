"""
LSADRA V4 — Central ingestion orchestrator.

Routes raw log lines from any source to the correct V4 parser via
auto-detection or source hint, then returns unified event dicts ready
for storage and downstream ML/rule detection.

Existing V3 parsers (LinuxSSHParser, WindowsLogonParser) are wrapped
in thin adapter classes and loaded first to preserve V3 behaviour.

Integrates with the FastAPI ingest endpoint and APScheduler health jobs.

[GLASSWING ALIGNMENT — central ingestion orchestrator]
[V4 ENHANCEMENT — gap: multi-source ingestion]
"""

import logging
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional

from lsadra.ingestion.base_parser import BaseParser
from lsadra.ingestion.syslog_parser import SyslogParser
from lsadra.ingestion.windows_event_parser import WindowsEventParser
from lsadra.ingestion.network_flow_parser import NetworkFlowParser
from lsadra.ingestion.endpoint_parser import EndpointParser

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# V3-compatibility adapters
# ---------------------------------------------------------------------------


class _SSHParserAdapter(BaseParser):
    """
    Thin adapter wrapping the existing V3 LinuxSSHParser.

    Converts the V3 event schema to the unified V4 schema so SSH events
    flow through the same pipeline without modification to the original class.

    [DESIGN CHOICE] Adapter pattern preserves V3 parser unchanged while
    enabling it to participate in the V4 IngestionManager chain.
    """

    def __init__(self) -> None:
        """Initialise the underlying V3 parser."""
        from lsadra.ingestion.parsers_linux import LinuxSSHParser
        self._v3 = LinuxSSHParser()

    @property
    def source_type(self) -> str:
        return "ssh_log"

    def can_parse(self, raw_line: str) -> bool:
        """Return True if line contains SSH auth patterns."""
        return "sshd[" in raw_line and (
            "Accepted " in raw_line or "Failed " in raw_line
            or "session" in raw_line or "sudo" in raw_line.lower()
        )

    def parse(self, raw_line: str, device_id: str) -> Optional[Dict[str, Any]]:
        """Parse via LinuxSSHParser and map to V4 schema."""
        v3 = self._v3.parse(raw_line.strip(), device_id=device_id)
        if v3 is None:
            return None
        return {
            "timestamp":   v3.get("timestamp", ""),
            "source_type": self.source_type,
            "source_ip":   v3.get("source_ip"),
            "dest_ip":     None,
            "username":    v3.get("effective_username"),
            "event_type":  v3.get("event_type", "unknown"),
            "success":     "accepted" in str(v3.get("event_type", "")).lower(),
            "raw":         v3.get("raw_message", raw_line)[:2048],
            "device_id":   device_id,
            "host":        v3.get("host", ""),  # syslog hostname, not the device ID
            "extra":       v3.get("attributes", {}),
        }


# Source-hint → parser class mapping for O(1) routed lookups
_HINT_MAP: Dict[str, str] = {
    "ssh":      "_SSHParserAdapter",
    "syslog":   "SyslogParser",
    "windows":  "WindowsEventParser",
    "network":  "NetworkFlowParser",
    "endpoint": "EndpointParser",
}


class IngestionManager:
    """
    Central ingestion orchestrator for LSADRA V4.

    Accepts raw log lines from any source, auto-detects the format,
    routes to the correct parser, and returns a unified event dict.

    Parser order matters: SSH is checked first (to avoid syslog stealing
    pure SSH lines), then syslog, Windows, network, endpoint.

    Statistics are tracked per source_type for the health dashboard.

    [GLASSWING ALIGNMENT — central ingestion orchestrator]
    [V4 ENHANCEMENT — gap: multi-source ingestion]
    """

    def __init__(self) -> None:
        """
        Initialise the ordered parser chain.

        V3 SSH adapter is loaded first to preserve existing V3 behaviour.
        """
        self.parsers: List[BaseParser] = [
            _SSHParserAdapter(),     # V3 compatibility — always first
            SyslogParser(),
            WindowsEventParser(),
            NetworkFlowParser(),
            EndpointParser(),
        ]
        # Per-source stats: {source_type: {"events": int, "errors": int, "last": str|None}}
        self._stats: Dict[str, Dict[str, Any]] = {
            p.source_type: {"events": 0, "errors": 0, "last_event": None}
            for p in self.parsers
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest_line(
        self, raw_line: str, device_id: str, hint: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Parse a single raw log line into a unified V4 event dict.

        Auto-detects format by trying each parser in chain order.
        If *hint* is provided it narrows the search to the matching parser.

        [GLASSWING ALIGNMENT — central ingestion orchestrator]

        Args:
            raw_line:  A single raw log line from any supported source.
            device_id: ID of the originating device.
            hint:      Optional source type hint: "ssh"|"syslog"|"windows"
                       |"network"|"endpoint".  If None, auto-detects.

        Returns:
            Unified event dict, or None if no parser can handle the line.
        """
        if not raw_line or not raw_line.strip():
            return None

        parsers = self._select_parsers(hint)
        for parser in parsers:
            try:
                if not parser.can_parse(raw_line):
                    continue
                event = parser.parse(raw_line, device_id)
                if event is not None:
                    if parser.validate_output(event):
                        self._record_success(parser.source_type)
                        return event
                    else:
                        logger.debug(
                            "Parser %s produced invalid schema for line: %.120s",
                            type(parser).__name__, raw_line,
                        )
            except Exception:
                self._record_error(parser.source_type)
                logger.exception(
                    "Parser %s raised exception on line: %.120s",
                    type(parser).__name__, raw_line,
                )
        return None

    def ingest_file(
        self, filepath: str, device_id: str, hint: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Read and parse an entire log file.

        [GLASSWING ALIGNMENT — central ingestion orchestrator]

        Args:
            filepath:  Path to the log file on disk.
            device_id: Originating device ID.
            hint:      Optional parser hint.

        Returns:
            List of unified event dicts (unparseable lines are skipped).
        """
        results: List[Dict[str, Any]] = []
        try:
            path = Path(filepath)
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    event = self.ingest_line(line, device_id, hint)
                    if event is not None:
                        results.append(event)
        except OSError:
            logger.exception("IngestionManager.ingest_file: cannot read %s", filepath)
        return results

    def ingest_stream(
        self, stream: Iterator[str], device_id: str, hint: Optional[str] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Yield unified events from a file-like stream, one line at a time.

        [GLASSWING ALIGNMENT — central ingestion orchestrator]

        Args:
            stream:    Any iterable producing raw log lines.
            device_id: Originating device ID.
            hint:      Optional parser hint.

        Yields:
            Unified event dicts.
        """
        for raw_line in stream:
            event = self.ingest_line(raw_line, device_id, hint)
            if event is not None:
                yield event

    def get_source_stats(self) -> Dict[str, Any]:
        """
        Return per-source ingestion statistics.

        Used by the health-check scheduler job and GET /api/v1/ingest/stats.

        Returns:
            Dict mapping source_type → {"events", "errors", "last_event"}.
        """
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _select_parsers(self, hint: Optional[str]) -> List[BaseParser]:
        """Return the parser list filtered by hint (if provided)."""
        if hint is None:
            return self.parsers
        hint_lower = hint.lower()
        filtered = [p for p in self.parsers if p.source_type.startswith(hint_lower)
                    or (hint_lower == "ssh" and isinstance(p, _SSHParserAdapter))]
        return filtered if filtered else self.parsers

    def _record_success(self, source_type: str) -> None:
        """Increment event counter and update last_event timestamp."""
        from datetime import datetime
        bucket = self._stats.setdefault(
            source_type, {"events": 0, "errors": 0, "last_event": None}
        )
        bucket["events"] += 1
        bucket["last_event"] = datetime.utcnow().isoformat()

    def _record_error(self, source_type: str) -> None:
        """Increment parse error counter for a source type."""
        bucket = self._stats.setdefault(
            source_type, {"events": 0, "errors": 0, "last_event": None}
        )
        bucket["errors"] += 1
