"""
LSADRA V4 — Network flow / connection log parser.

Supports multiple formats:
  - NetFlow-style CSV: timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets
  - Simple connection log: timestamp src_ip:port -> dst_ip:port protocol bytes
  - Firewall DENY logs: pfSense/iptables DENY format

Enriches events with flags:
  - port_scan_indicator (many dst_ports from same src in short window)
  - large_transfer (bytes > threshold)
  - unusual_port (dst_port not in common services)
  - internal_to_internal (RFC 1918 → RFC 1918)

[V4 ENHANCEMENT — gap: multi-source ingestion]
[Capability: multi-source unified schema]
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional, Set

from lsadra.ingestion.base_parser import BaseParser

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
COMMON_PORTS: Set[int] = {
    80,
    443,
    22,
    21,
    25,
    53,
    110,
    143,
    993,
    995,
    3389,
    5985,
    8080,
    8443,
}
LARGE_TRANSFER_BYTES: int = 10_000_000  # 10 MB
_RFC1918_PREFIXES = (
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
)

# ---------------------------------------------------------------------------
# Regex patterns for each format
# ---------------------------------------------------------------------------
# NetFlow CSV: 2024-01-01T00:00:00,1.2.3.4,5.6.7.8,12345,443,TCP,512,4
_NETFLOW_RE = re.compile(
    r"^(?P<ts>[^,]+),(?P<src_ip>\d[\d.]+),(?P<dst_ip>\d[\d.]+),"
    r"(?P<src_port>\d+),(?P<dst_port>\d+),(?P<proto>\w+),"
    r"(?P<bytes>\d+),(?P<packets>\d+)$"
)

# Simple connection: "2024-01-01T00:00:00 1.2.3.4:1234 -> 5.6.7.8:80 TCP 512"
_CONNLOG_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)\s+(?P<proto>\w+)(?:\s+(?P<bytes>\d+))?$"
)

# iptables/pfSense DENY: "... SRC=1.2.3.4 DST=5.6.7.8 ... DPT=22 ..."
# Firewall lines ("... SRC=<ip> ... DST=<ip> ... DPT=<port> [... SPT=<port>]")
# are matched field by field (_match_firewall) rather than with one pattern:
# a single regex with several unbounded ".*" gaps backtracks super-linearly on
# long, attacker-shaped lines.
_FW_SRC_RE = re.compile(r"SRC=([\d.]+)")
_FW_DST_RE = re.compile(r"DST=([\d.]+)")
_FW_DPT_RE = re.compile(r"DPT=(\d+)")
_FW_SPT_RE = re.compile(r"SPT=(\d+)")


def _last_field(line: str, rx: "re.Pattern[str]", key: str, lo: int, hi: int):
    """Last match of ``rx`` (which starts with ``key``) inside line[lo:hi]."""
    at = hi
    while True:
        at = line.rfind(key, lo, at + len(key) - 1)
        if at < 0:
            return None
        m = rx.match(line, at, hi)
        if m:
            return m


def _match_firewall(line: str) -> Optional[Dict[str, Optional[str]]]:
    """Fields of a firewall log line, with the same choices a greedy
    ``SRC=..*DST=..*DPT=..(?:.*SPT=..)?`` search would make, in linear time."""
    src = _FW_SRC_RE.search(line)
    if not src:
        return None
    dpt = _last_field(line, _FW_DPT_RE, "DPT=", src.end(), len(line))
    if not dpt:
        return None
    dst = _last_field(line, _FW_DST_RE, "DST=", src.end(), dpt.start())
    if not dst:
        return None
    spt = _last_field(line, _FW_SPT_RE, "SPT=", dpt.end(), len(line))
    return {
        "src_ip": src.group(1),
        "dst_ip": dst.group(1),
        "dst_port": dpt.group(1),
        "src_port": spt.group(1) if spt else None,
    }


_FIREWALL_TS_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")


class NetworkFlowParser(BaseParser):
    """
    Network flow and connection log parser.

    Normalises NetFlow CSV, simple connection logs, and firewall deny logs
    into the unified V4 event schema with enriched flow indicators.

    [Capability: multi-source unified schema]
    [V4 ENHANCEMENT — gap: multi-source ingestion]
    """

    @property
    def source_type(self) -> str:
        """Returns the source type label for this parser."""
        return "network_flow"

    def can_parse(self, raw_line: str) -> bool:
        """
        Returns True if line matches any supported network flow format.

        Args:
            raw_line: Raw network log line.

        Returns:
            True if the line is a recognisable network flow entry.
        """
        line = raw_line.strip()
        if not line:
            return False
        if _NETFLOW_RE.match(line):
            return True
        if _CONNLOG_RE.match(line):
            return True
        if _match_firewall(line):
            return True
        return False

    def parse(self, raw_line: str, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Parse a network flow line into the unified V4 event schema.

        Args:
            raw_line:  Raw network flow line.
            device_id: Originating device identifier.

        Returns:
            Unified event dict or None if unrecognised.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        result = (
            self._parse_netflow(raw_line)
            or self._parse_connlog(raw_line)
            or self._parse_firewall(raw_line)
        )
        if result is None:
            return None

        ts, src_ip, dst_ip, src_port, dst_port, proto, byte_count, is_deny = result
        extra = self._build_extra(src_ip, dst_ip, src_port, dst_port, proto, byte_count)

        event_type = "firewall_deny" if is_deny else "connection"
        success = not is_deny

        return {
            "timestamp": ts,
            "source_type": self.source_type,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "username": None,
            "event_type": event_type,
            "success": success,
            "raw": raw_line[:2048],
            "device_id": device_id,
            "extra": extra,
        }

    # ------------------------------------------------------------------
    # Format parsers
    # ------------------------------------------------------------------

    def _parse_netflow(self, line: str) -> Optional[tuple]:
        """Parse NetFlow-style CSV line."""
        m = _NETFLOW_RE.match(line)
        if not m:
            return None
        ts = self._normalise_ts(m.group("ts"))
        return (
            ts,
            m.group("src_ip"),
            m.group("dst_ip"),
            int(m.group("src_port")),
            int(m.group("dst_port")),
            m.group("proto"),
            int(m.group("bytes")),
            False,
        )

    def _parse_connlog(self, line: str) -> Optional[tuple]:
        """Parse simple connection log line."""
        m = _CONNLOG_RE.match(line)
        if not m:
            return None
        ts = self._normalise_ts(m.group("ts"))
        return (
            ts,
            m.group("src_ip"),
            m.group("dst_ip"),
            int(m.group("src_port")),
            int(m.group("dst_port")),
            m.group("proto"),
            int(m.group("bytes") or 0),
            False,
        )

    def _parse_firewall(self, line: str) -> Optional[tuple]:
        """Parse iptables/pfSense DENY firewall log line."""
        m = _match_firewall(line)
        if not m:
            return None
        ts_m = _FIREWALL_TS_RE.match(line)
        ts = self._normalise_ts(ts_m.group("ts")) if ts_m else datetime.utcnow().isoformat()
        src_port = int(m["src_port"]) if m["src_port"] else 0
        return (
            ts,
            m["src_ip"],
            m["dst_ip"],
            src_port,
            int(m["dst_port"]),
            "TCP",
            0,
            True,
        )

    # ------------------------------------------------------------------
    # Enrichment helpers
    # ------------------------------------------------------------------

    def _build_extra(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: str,
        byte_count: int,
    ) -> Dict[str, Any]:
        """Build the enriched extra dict with flow-level indicators."""
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "bytes": byte_count,
            "large_transfer": byte_count > LARGE_TRANSFER_BYTES,
            "unusual_port": dst_port not in COMMON_PORTS,
            "internal_to_internal": (self._is_rfc1918(src_ip) and self._is_rfc1918(dst_ip)),
            # port_scan_indicator is computed post-hoc in feature extraction
            "port_scan_indicator": False,
        }

    def _is_rfc1918(self, ip: str) -> bool:
        """Return True if the IP address is in an RFC 1918 private range."""
        return any(ip.startswith(pfx) for pfx in _RFC1918_PREFIXES)

    def _normalise_ts(self, ts_str: str) -> str:
        """Normalise various timestamp formats to ISO 8601."""
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt.isoformat()
            except ValueError:
                continue
        return datetime.utcnow().isoformat()
