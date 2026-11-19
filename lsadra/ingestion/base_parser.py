"""
LSADRA V4 — Abstract base parser.

Defines the unified event schema contract all V4 parsers must satisfy.
Existing V3 parsers (LinuxSSHParser, WindowsLogonParser) are not replaced —
they continue to work via the IngestionManager adapter.

[Capability: multi-source unified schema]
[V4 ENHANCEMENT — gap: multi-source ingestion]
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Unified V4 event schema (all parsers must produce this shape)
# ---------------------------------------------------------------------------
REQUIRED_SCHEMA_FIELDS: tuple = (
    "timestamp",   # ISO 8601 string
    "source_type", # "ssh_log"|"syslog"|"windows_event"|"network_flow"|"endpoint"
    "source_ip",   # str (may be None for some endpoint events)
    "dest_ip",     # str | None
    "username",    # str | None
    "event_type",  # normalised action label
    "success",     # bool
    "raw",         # original raw line
    "device_id",   # originating device
    "extra",       # dict of parser-specific fields
)


class BaseParser(ABC):
    """
    Abstract base for all V4 ingestion parsers.

    Enforces the unified output schema across all sources, enabling
    IngestionManager to treat SSH, syslog, Windows, network, and endpoint
    events identically downstream.

    [Capability: multi-source unified schema]
    [DESIGN CHOICE] ABC enforces contract at class-definition time; validation
    at runtime guards against parser bugs without crashing the ingest pipeline.
    """

    @abstractmethod
    def can_parse(self, raw_line: str) -> bool:
        """
        Returns True if this parser can handle the given raw line.

        Args:
            raw_line: A single raw log line (may be XML, CSV, or plain text).

        Returns:
            True if the parser recognises the format; False otherwise.
        """

    @abstractmethod
    def parse(self, raw_line: str, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Parse a raw log line into the unified V4 event schema.

        Args:
            raw_line:  Single line of raw log text.
            device_id: ID of the originating device (from registration).

        Returns:
            Unified event dict, or None if the line is not parseable /
            not security-relevant.
        """

    def validate_output(self, event: Dict[str, Any]) -> bool:
        """
        Validate that a parsed event dict contains all required schema fields.

        [DESIGN CHOICE] Soft validation — returns bool rather than raising,
        so IngestionManager can count parse errors without crashing.

        Args:
            event: Parsed event dict to validate.

        Returns:
            True if all required fields are present; False otherwise.
        """
        return all(field in event for field in REQUIRED_SCHEMA_FIELDS)

    @property
    def source_type(self) -> str:
        """
        Short label for this parser's source type.

        Used by IngestionManager for hint-based routing and stats tracking.
        Subclasses should override this property.
        """
        return "unknown"
