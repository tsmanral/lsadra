"""
LSADRA — IP geolocation resolver.

Fills ``ip_geolocation`` for public source IPs in ``normalized_events`` from
the local MaxMind-format database (``lsadra.intel.geo``). No IP address is sent
to any outside service. Earlier versions queried ipinfo.io and Nominatim; that
leaked every observed IP to a third party and is gone.
"""

import logging

from lsadra.intel import geo
from lsadra.storage.database import get_unresolved_ips, upsert_ip_geolocation

logger = logging.getLogger(__name__)


def run(limit: int = 1000) -> int:
    """Resolve up to ``limit`` unresolved IPs. Returns how many were stored."""
    if geo.database_path() is None:
        logger.info("Geo resolution skipped: no local geolocation database "
                    "(run `python -m lsadra.intel geo-update`).")
        return 0
    unresolved = get_unresolved_ips(limit=limit)
    resolved = 0
    for ip in unresolved:
        info = geo.lookup(ip)
        if info is None:
            # Private, reserved or unknown: record it so it is not retried forever.
            upsert_ip_geolocation(ip, 0.0, 0.0, "", "")
            continue
        upsert_ip_geolocation(
            ip,
            info.get("latitude") or 0.0,
            info.get("longitude") or 0.0,
            info.get("city", ""),
            info.get("country_code", ""),
        )
        resolved += 1
    logger.info("Geo resolution: resolved %d/%d IPs.", resolved, len(unresolved))
    return resolved
