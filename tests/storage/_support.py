"""Shared constants and builders for the storage contract suite (synthetic data only)."""

from typing import Any, Dict, List

USER_ID = "user-1"
USERNAME = "alice"
DEVICE_ID = "dev-1"


def make_event(**overrides: Any) -> Dict[str, Any]:
    """A minimal valid normalized event for the seeded device/user."""
    event: Dict[str, Any] = {
        "timestamp": "2026-01-01T00:00:00",
        "device_id": DEVICE_ID,
        "user_id": USER_ID,
        "host": "host-1",
        "effective_username": "svc",
        "source_ip": "192.0.2.10",
        "event_type": "auth_failure",
        "raw_message": "synthetic event",
        "attributes": {"k": "v"},
    }
    event.update(overrides)
    return event


def transactions(statements: List[str]) -> List[str]:
    """The transaction-control statements in one connection traced by ``traced``."""
    return [s.strip() for s in statements if s.strip() in ("BEGIN", "COMMIT", "ROLLBACK")]
