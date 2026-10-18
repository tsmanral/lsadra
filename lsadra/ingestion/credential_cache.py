"""
Bounded TTL cache of verified device credentials (D7 Option A, S2-5).

bcrypt verification of the device API key was ~93% of ingest request latency
(benchmarks/baseline-2026-09-30.json). An agent sends the same key on every
batch, so after one successful bcrypt verify the result is remembered for a
short time and the repeat verify is skipped.

What is stored, per device id:

* an HMAC-SHA256 **fingerprint** of the key under a random per-process secret —
  never the key itself, and useless outside this process;
* the exact ``api_key_hash`` the key was verified against;
* the absolute expiry (verification time + TTL; a hit does not extend it).

A hit requires all three to match: same device id, the device row's current
``api_key_hash`` equal to the one cached (so a re-keyed device misses), and the
presented key's fingerprint equal to the cached one (constant-time compare).
Anything else is a miss, and the caller falls back to the full bcrypt path —
so the cache can only skip a verify whose answer is already known to be "yes"
for that exact key and hash. Failed verifications are never cached.

The caller still reads the device row on every request: a deleted device is
still a 401, and the returned row is always fresh.

Thread-safe: ``_authenticate_device`` is a sync dependency and runs in the
threadpool.
"""

import hashlib
import hmac
import os
import threading
import time
from collections import OrderedDict
from typing import Callable, NamedTuple, Optional


class _Entry(NamedTuple):
    fingerprint: bytes
    stored_hash: str
    expires_at: float


class VerifiedCredentialCache:
    """LRU-bounded, TTL-expiring set of (device id, key, stored hash) verifications."""

    def __init__(
        self,
        ttl_seconds: float,
        max_entries: int,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._ttl = float(ttl_seconds)
        self._max_entries = max_entries
        self._clock = clock
        self._secret = os.urandom(32)
        self._entries: "OrderedDict[str, _Entry]" = OrderedDict()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._ttl > 0

    def _fingerprint(self, api_key: str) -> bytes:
        return hmac.new(self._secret, api_key.encode("utf-8"), hashlib.sha256).digest()

    def is_verified(self, device_id: str, api_key: str, stored_hash: str) -> bool:
        """True only if this exact key was verified against this exact hash within the TTL."""
        if not self.enabled:
            return False
        fingerprint = self._fingerprint(api_key)
        now = self._clock()
        with self._lock:
            entry = self._entries.get(device_id)
            if entry is None:
                return False
            if now >= entry.expires_at or entry.stored_hash != stored_hash:
                # Stale (expired or the device was re-keyed): drop it.
                del self._entries[device_id]
                return False
            # A mismatched key leaves the entry alone: evicting it would let
            # anyone who knows a device id force that device back onto bcrypt.
            if not hmac.compare_digest(entry.fingerprint, fingerprint):
                return False
            self._entries.move_to_end(device_id)
            return True

    def remember(self, device_id: str, api_key: str, stored_hash: str) -> None:
        """Record a successful bcrypt verification. Call only after checkpw returned True."""
        if not self.enabled:
            return
        entry = _Entry(self._fingerprint(api_key), stored_hash, self._clock() + self._ttl)
        with self._lock:
            self._entries[device_id] = entry
            self._entries.move_to_end(device_id)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def invalidate(self, device_id: Optional[str] = None) -> None:
        """Forget one device (or every device when *device_id* is None)."""
        with self._lock:
            if device_id is None:
                self._entries.clear()
            else:
                self._entries.pop(device_id, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
