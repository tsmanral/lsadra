"""
Compatibility shim: threat intel now lives in ``lsadra.intel`` (ADR 0004).

Kept so older imports keep working. Nothing here returns a simulated score.
"""

from typing import Any, Dict, Optional

from lsadra import intel
from lsadra.intel.feeds import query_abuseipdb  # noqa: F401  (re-exported)


def get_ip_reputation(ip_address: str) -> Dict[str, Any]:
    """Locally known intel for an IP in the old flat shape, or a not-queried marker."""
    view: Optional[Dict[str, Any]] = intel.legacy_view(intel.lookup_ip(ip_address))
    if view:
        view["ip"] = ip_address
        return view
    return {"ip": ip_address, "abuse_score": None, "status": "not_queried"}
