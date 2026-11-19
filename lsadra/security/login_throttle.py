"""Login throttling (G-10, ASVS 5.0 V6.3.1, OWASP API2).

Failed logins are counted per username and per client IP over a sliding
window. The check runs *before* the password hash is verified, so a throttled
guess costs the server no bcrypt work and tells the caller nothing about the
password. A successful login clears the username's counter (not the IP's, so
one valid account cannot be used to reset an IP that is spraying others).

State is in memory and bounded (least recently used keys are dropped first),
like the existing per-device rate limiter.
"""

import threading
import time
from collections import OrderedDict, deque
from typing import Deque, Optional

from lsadra import config

_MAX_KEYS = 10_000


class _FailureLog:
    def __init__(self, max_keys: int = _MAX_KEYS) -> None:
        self._entries: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._max_keys = max_keys

    def _prune(self, key: str, now: float, window: float) -> Deque[float]:
        q = self._entries.get(key)
        if q is None:
            return deque()
        while q and q[0] <= now - window:
            q.popleft()
        if not q:
            del self._entries[key]
        return q

    def count(self, key: str, now: float, window: float) -> int:
        return len(self._prune(key, now, window))

    def oldest(self, key: str) -> Optional[float]:
        q = self._entries.get(key)
        return q[0] if q else None

    def add(self, key: str, now: float, window: float) -> None:
        self._prune(key, now, window)
        q = self._entries.setdefault(key, deque())
        q.append(now)
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_keys:
            self._entries.popitem(last=False)

    def clear(self, key: str) -> None:
        self._entries.pop(key, None)

    def reset(self) -> None:
        self._entries.clear()


class LoginThrottle:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._users = _FailureLog()
        self._ips = _FailureLog()

    @staticmethod
    def _user_key(username: str) -> str:
        return username.strip().lower()

    def retry_after(self, username: str, ip: str, now: Optional[float] = None) -> int:
        """Seconds the caller must wait, or 0 if a login attempt may proceed."""
        now = time.time() if now is None else now
        window = float(config.LOGIN_FAILURE_WINDOW_SECONDS)
        waits = []
        with self._lock:
            for log, key, limit in (
                (self._users, self._user_key(username), config.LOGIN_MAX_FAILURES_PER_USER),
                (self._ips, ip, config.LOGIN_MAX_FAILURES_PER_IP),
            ):
                if log.count(key, now, window) >= limit:
                    oldest = log.oldest(key) or now
                    waits.append(max(1, int(oldest + window - now) + 1))
        return max(waits) if waits else 0

    def record_failure(self, username: str, ip: str, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        window = float(config.LOGIN_FAILURE_WINDOW_SECONDS)
        with self._lock:
            self._users.add(self._user_key(username), now, window)
            self._ips.add(ip, now, window)

    def record_success(self, username: str) -> None:
        with self._lock:
            self._users.clear(self._user_key(username))

    def reset(self) -> None:
        with self._lock:
            self._users.reset()
            self._ips.reset()


login_throttle = LoginThrottle()
