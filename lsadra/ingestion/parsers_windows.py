"""
LSADRA V2 — Windows Security Event Log parser.

Converts Windows Security event XML (Event IDs 4624, 4625, 4672, 4648)
into normalized event dictionaries.

.. note::
    This module is a **design skeleton**.  Full implementation depends on the
    Windows agent feeding XML event data over HTTPS.  The parser is included
    so the backend is ready when the Windows agent is built.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Optional

# Map Windows logon-type codes to human-readable labels
_LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}


class WindowsLogonParser:
    """Parse Windows Security Event Log XML into normalized events."""

    # Event IDs we care about
    SUPPORTED_EVENT_IDS = {"4624", "4625", "4672", "4648"}

    @staticmethod
    def parse(
        event_xml: str,
        device_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Parse a single Windows Security event XML string.

        Args:
            event_xml: Raw XML string for one event (as returned by
                ``wevtutil qe Security``).
            device_id: Registered device that produced this event.
            user_id: Owner of the device.

        Returns:
            Normalized event dict, or *None* if unrecognised.
        """
        try:
            root = ET.fromstring(event_xml)
        except ET.ParseError:
            return None

        # Namespace varies by Windows version; strip it
        ns = ""
        m = re.match(r"\{(.*?)\}", root.tag)
        if m:
            ns = m.group(1)
        nsmap = {"ns": ns} if ns else {}

        def _find(path: str) -> Optional[str]:
            el = root.find(path, nsmap)
            return el.text if el is not None else None

        # Extract core system fields
        event_id = _find(".//ns:System/ns:EventID") if ns else _find(".//System/EventID")
        if event_id not in WindowsLogonParser.SUPPORTED_EVENT_IDS:
            return None

        time_created_el = root.find(".//{%s}System/{%s}TimeCreated" % (ns, ns)) if ns else root.find(".//System/TimeCreated")
        ts_raw = time_created_el.get("SystemTime", "") if time_created_el is not None else ""
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.utcnow()

        computer = _find(".//ns:System/ns:Computer") if ns else _find(".//System/Computer")

        # Extract EventData fields
        data_fields: Dict[str, str] = {}
        for data_el in root.iter("{%s}Data" % ns if ns else "Data"):
            name = data_el.get("Name", "")
            data_fields[name] = data_el.text or ""

        username = data_fields.get("TargetUserName", "")
        source_ip = data_fields.get("IpAddress", "")
        logon_type_code = data_fields.get("LogonType", "")
        logon_type = _LOGON_TYPES.get(logon_type_code, logon_type_code)

        # Map event IDs to friendly event types
        # Canonical event types (lsadra/detection/event_types.py)
        event_type_map = {
            "4624": "auth_success",
            "4625": "auth_failure",
            "4672": "privileged_logon",
            "4648": "auth_success",
        }

        return {
            "timestamp": ts.isoformat(),
            "host": computer or "",
            "device_id": device_id,
            "user_id": user_id,
            "effective_username": username,
            "source_ip": source_ip if source_ip and source_ip != "-" else None,
            "event_type": event_type_map.get(event_id, "other"),
            "raw_message": event_xml[:4096],
            "attributes": {
                "event_id": event_id,
                "logon_type": logon_type,
                "domain": data_fields.get("TargetDomainName", ""),
                "status": data_fields.get("Status", ""),
                "sub_status": data_fields.get("SubStatus", ""),
            },
        }
