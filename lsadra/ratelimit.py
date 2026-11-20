"""
Bounded sliding-window rate limiter (§6 #5).

The previous per-endpoint rate limiters used an unbounded ``defaultdict`` keyed
by device_id / client IP, so every distinct — including dead or spoofed —
identifier added a permanent entry: a slow memory-exhaustion vector. This
limiter keeps at most ``max_keys`` windows (LRU eviction) and opportunistically
drops idle keys whose window has fully aged out.

Not thread-safe on its own; callers touch it synchronously under the FastAPI
event loop, which is sufficient here. Persistence is descoped to M1.
"""

from collections import OrderedDict, deque


class SlidingWindowRateLimiter:
    """Fixed-window-per-key limiter with a hard LRU cap on the number of keys."""

    def __init__(self, limit: int, window_seconds: float = 60.0, max_keys: int = 10_000):
        self._limit = limit
        self._window = float(window_seconds)
        self._max_keys = max_keys
        self._hits: "OrderedDict[str, deque]" = OrderedDict()
        self._last_sweep = 0.0

    def allow(self, key: str, now: float) -> bool:
        """Record a hit for ``key`` at time ``now``; return False if over limit."""
        existed = key in self._hits
        window = self._hits.get(key)
        if window is None:
            window = deque()
            self._hits[key] = window  # inserted as most-recently-used
        else:
            self._hits.move_to_end(key)  # mark most-recently-used

        cutoff = now - self._window
        while window and window[0] <= cutoff:
            window.popleft()

        allowed = len(window) < self._limit
        if allowed:
            window.append(now)

        # Enforce the key cap. NEVER evict an ACTIVE key to make room: evicting
        # it resets its window, which would let an attacker bypass the limit for
        # any key (including their own) by flooding distinct keys until the
        # victim is pushed out. Evict only an idle (aged-out) key; if the cap is
        # full of active keys, drop THIS new key and deny — fail closed.
        # (§6 #5 + commit-review follow-up)
        self._maybe_sweep(now)
        if len(self._hits) > self._max_keys:
            if not self._evict_one_idle(now) and not existed:
                del self._hits[key]
                return False

        return allowed

    def _evict_one_idle(self, now: float) -> bool:
        """Evict one idle (empty or fully aged-out) key, oldest-first. True if evicted."""
        cutoff = now - self._window
        victim = None
        for k, w in self._hits.items():  # OrderedDict iterates LRU-first
            if not w or w[-1] <= cutoff:
                victim = k
                break
        if victim is None:
            return False
        del self._hits[victim]
        return True

    def _maybe_sweep(self, now: float) -> None:
        """Throttled idle-key eviction (at most once per window)."""
        if now - self._last_sweep < self._window:
            return
        self._last_sweep = now
        cutoff = now - self._window
        stale = [k for k, w in self._hits.items() if not w or w[-1] <= cutoff]
        for k in stale:
            del self._hits[k]

    def __len__(self) -> int:
        return len(self._hits)

    def __contains__(self, key: str) -> bool:
        return key in self._hits
