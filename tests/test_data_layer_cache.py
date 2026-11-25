"""The dashboard data layer must work without Streamlit (base install)."""

import time

from lsadra.api.data_layer import _ttl_cache


def test_ttl_cache_memoises_within_ttl_and_expires(monkeypatch):
    calls = []

    @_ttl_cache(ttl=30)
    def fetch(device_id, start=None):
        calls.append((device_id, start))
        return [{"device": device_id}]

    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])

    assert fetch("d1", start="a") == [{"device": "d1"}]
    assert fetch("d1", start="a") == [{"device": "d1"}]
    assert len(calls) == 1  # second call served from cache

    fetch("d2", start="a")
    assert len(calls) == 2  # different arguments, separate entry

    now[0] += 31
    fetch("d1", start="a")
    assert len(calls) == 3  # expired after ttl


def test_ttl_cache_returns_copies_and_supports_clear():
    @_ttl_cache(ttl=60)
    def fetch():
        return [{"n": 1}]

    first = fetch()
    first.append("mutated")
    assert fetch() == [{"n": 1}]  # caller mutation does not leak into the cache

    fetch.clear()
    assert fetch() == [{"n": 1}]
