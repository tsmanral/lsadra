"""
LSADRA — object-level authorization helpers.

Role checks (``lsadra.auth.require_role``) decide *what kind* of action a user
may take. These helpers decide *which objects* the action may touch: an ADMIN
sees every device and incident, everyone else only the devices registered to
their own account and the incidents raised on those devices.

Every route that takes a device or incident id from the client must check it
here before reading or changing anything. A denied object is reported the same
way as a missing one (404), so ids belonging to other accounts cannot be probed.

The functions are synchronous (SQLite reads) and are meant to run inside the
handler's existing ``run_in_threadpool`` call.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from lsadra.storage.database import get_device, get_devices_for_user, get_incident


def is_admin(user: Dict[str, Any]) -> bool:
    return user.get("role") == "ADMIN"


def owns_device(user: Dict[str, Any], device_id: Optional[str]) -> bool:
    """True if *device_id* exists and *user* may act on it."""
    if not device_id:
        return False
    device = get_device(device_id)
    if device is None:
        return False
    return is_admin(user) or device.get("user_id") == user.get("user_id")


def owned_incident(user: Dict[str, Any], incident_id: int) -> Optional[Dict[str, Any]]:
    """The incident row if it exists and *user* may act on it, else None."""
    incident = get_incident(incident_id)
    if incident is None:
        return None
    if is_admin(user) or owns_device(user, incident.get("device_id")):
        return incident
    return None


def visible_device_ids(user: Dict[str, Any]) -> Optional[List[str]]:
    """Device ids *user* may see, or None meaning "all devices" (ADMIN)."""
    if is_admin(user):
        return None
    return [d["id"] for d in get_devices_for_user(user["user_id"])]
