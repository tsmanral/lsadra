"""
LSADRA security regression — §6 #5: unbounded rate-limit keys.

Attacker story: the per-device / per-IP rate limiters kept one window per
distinct identifier in an unbounded dict. An attacker cycling through millions
of spoofed device IDs (or source IPs) forced unbounded memory growth — a
denial-of-service via memory exhaustion. The fix caps tracked keys with an LRU
and evicts idle keys, while still enforcing the per-window request limit.

Pre-fix there is no bounded limiter (import fails / growth is unbounded); these
assertions pin the bounded behavior.
"""

from lsadra.ratelimit import SlidingWindowRateLimiter


def test_over_limit_is_blocked():
    rl = SlidingWindowRateLimiter(limit=3, window_seconds=60, max_keys=100)
    t = 1000.0
    assert rl.allow("k", t) is True
    assert rl.allow("k", t) is True
    assert rl.allow("k", t) is True
    assert rl.allow("k", t) is False  # 4th within the window is blocked


def test_keys_are_bounded_by_max_keys():
    """CORE regression: distinct (spoofed) keys must not grow without bound."""
    rl = SlidingWindowRateLimiter(limit=10, window_seconds=60, max_keys=50)
    t = 1000.0
    for i in range(5000):
        rl.allow(f"spoofed-{i}", t)
    assert len(rl) <= 50


def test_idle_keys_evicted_after_window():
    rl = SlidingWindowRateLimiter(limit=5, window_seconds=60, max_keys=1000)
    rl.allow("old", 1000.0)
    assert "old" in rl
    # Advance past the window and touch another key -> idle sweep drops "old".
    rl.allow("new", 1000.0 + 121)
    assert "old" not in rl
    assert "new" in rl


def test_window_slides_and_allows_after_expiry():
    rl = SlidingWindowRateLimiter(limit=1, window_seconds=60, max_keys=100)
    assert rl.allow("k", 1000.0) is True
    assert rl.allow("k", 1000.0) is False  # still within the window
    assert rl.allow("k", 1000.0 + 61) is True  # window elapsed -> allowed again


def test_distinct_key_flood_does_not_reset_active_counter():
    """Commit-review follow-up: LRU eviction must NOT let a flood of distinct
    keys reset an ACTIVE key's window (rate-limit bypass). An at-limit key must
    stay blocked even after the cap is pressured by many other keys.
    """
    rl = SlidingWindowRateLimiter(limit=2, window_seconds=60, max_keys=10)
    t = 1000.0
    assert rl.allow("victim", t) is True
    assert rl.allow("victim", t) is True
    assert rl.allow("victim", t) is False  # victim now at its limit

    # Flood many distinct keys within the same window to force cap pressure.
    for i in range(100):
        rl.allow(f"flood-{i}", t)

    # victim's counter must survive the flood — still blocked, no bypass —
    # and the limiter stays bounded.
    assert rl.allow("victim", t) is False
    assert len(rl) <= 10
