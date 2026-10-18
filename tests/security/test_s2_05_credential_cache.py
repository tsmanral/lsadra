"""
Security tests — S2-5 / D7 Option A: verified device-credential cache.

The cache lets `_authenticate_device` skip a repeat bcrypt verify. That is
only safe if it can never turn a "no" into a "yes", so every test here pins
one way it could: a wrong key, an expired entry, a re-keyed or deleted device,
an unbounded cache, a cached failure, or the key itself sitting in memory.
The refresh-ahead tests pin that a background re-verify can only renew an
entry after a fresh, passing bcrypt, and never brings back a revoked one.

Each load-bearing test names the guard whose removal makes it fail.

All data below is SYNTHETIC — obviously-fake device IDs and keys only.
"""

import threading

import bcrypt
import pytest
from fastapi import HTTPException

import lsadra.ingestion.api_ingestion as api_ingestion
from lsadra.ingestion.api_ingestion import _authenticate_device
from lsadra.ingestion.credential_cache import VerifiedCredentialCache
from lsadra.storage import database as db_module
from lsadra.storage.database import create_device, create_user
from tests.fixtures import setup_test_db

_DEVICE_ID = "test-device-cache-001"
_CORRECT_KEY = "test-secret-cache-abc123"
_WRONG_KEY = "test-wrong-cache-key-999"
_TTL = 60.0


class _Clock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def _hash(key: str) -> str:
    # Cost 4 keeps the suite fast; the cost the server uses is unchanged.
    return bcrypt.hashpw(key.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("utf-8")


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    setup_test_db(tmp_path)


@pytest.fixture
def clock(monkeypatch):
    """Swap in a fresh cache driven by a manual clock."""
    c = _Clock()
    monkeypatch.setattr(
        api_ingestion,
        "device_credential_cache",
        VerifiedCredentialCache(ttl_seconds=_TTL, max_entries=100, clock=c),
    )
    return c


class _DeferredExecutor:
    """Stands in for the refresh executor: holds jobs until a test runs them."""

    def __init__(self) -> None:
        self.jobs = []

    def submit(self, fn, *args):
        self.jobs.append((fn, args))

    def run_all(self) -> int:
        jobs, self.jobs = self.jobs, []
        for fn, args in jobs:
            fn(*args)
        return len(jobs)


@pytest.fixture(autouse=True)
def refresher(monkeypatch):
    """Background re-verifies run only when a test says so — deterministic counts."""
    executor = _DeferredExecutor()
    monkeypatch.setattr(api_ingestion, "_credential_refresh_executor", executor)
    return executor


@pytest.fixture
def checkpw_calls(monkeypatch):
    """Count real bcrypt verifies made by the auth dependency."""
    calls = []
    real = bcrypt.checkpw

    def counting(password, hashed):
        calls.append(password)
        return real(password, hashed)

    monkeypatch.setattr(api_ingestion.bcrypt, "checkpw", counting)
    return calls


@pytest.fixture
def device():
    create_user("user-cache", "user-cache", "synthetic-not-a-real-hash", "ANALYST")
    create_device(_DEVICE_ID, "user-cache", "test-host", "linux", _hash(_CORRECT_KEY))
    return _DEVICE_ID


def _set_hash(device_id: str, stored_hash: str) -> None:
    with db_module._connection() as conn:
        conn.execute("UPDATE devices SET api_key_hash = ? WHERE id = ?", (stored_hash, device_id))
        conn.commit()


def _delete(device_id: str) -> None:
    with db_module._connection() as conn:
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        conn.commit()


def _assert_401(device_id: str, key: str, detail: str = "Invalid API key.") -> None:
    with pytest.raises(HTTPException) as ei:
        _authenticate_device(x_device_id=device_id, x_api_key=key)
    assert ei.value.status_code == 401
    assert ei.value.detail == detail


# ── hit / miss ───────────────────────────────────────────────────────────────


def test_miss_then_hit_skips_bcrypt(device, clock, checkpw_calls):
    """First request verifies with bcrypt; the repeat within the TTL does not."""
    assert _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)["id"] == device
    assert len(checkpw_calls) == 1
    clock.now += _TTL - 1
    assert _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)["id"] == device
    assert len(checkpw_calls) == 1


def test_hit_returns_fresh_device_row(device, clock):
    """A hit still reads the device row: changes to it are visible at once."""
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    db_module.update_device_status(device, "ONLINE")
    assert _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)["status"] == "ONLINE"


# ── invalid / mismatch ───────────────────────────────────────────────────────


def test_wrong_key_rejected_on_cached_device(device, clock, checkpw_calls):
    """
    LOAD-BEARING: with the right key cached, a wrong key is still a 401 and
    goes through bcrypt. Fails if the fingerprint compare is dropped.
    """
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    _assert_401(device, _WRONG_KEY)
    _assert_401(device, "")
    _assert_401(device, "A" * 200)
    assert len(checkpw_calls) == 4


def test_wrong_key_does_not_evict_the_valid_entry(device, clock, checkpw_calls):
    """A forged request cannot push a real device back onto bcrypt."""
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    _assert_401(device, _WRONG_KEY)
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(checkpw_calls) == 2  # first verify + the wrong key; not the repeat


def test_cached_key_does_not_authenticate_another_device(device, clock):
    """
    LOAD-BEARING: the entry is keyed by device id. A key cached for device A
    is not accepted for device B. Fails if the cache ignores the device id.
    """
    other = "test-device-cache-002"
    create_device(other, "user-cache", "test-host-2", "linux", _hash("test-other-key-777"))
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    _assert_401(other, _CORRECT_KEY)


def test_failed_verification_is_never_cached(device, clock, checkpw_calls):
    """A wrong key that failed bcrypt is verified again (and fails) every time."""
    _assert_401(device, _WRONG_KEY)
    _assert_401(device, _WRONG_KEY)
    assert len(checkpw_calls) == 2
    assert len(api_ingestion.device_credential_cache) == 0


# ── expiry ───────────────────────────────────────────────────────────────────


def test_entry_expires_after_ttl(device, clock, checkpw_calls):
    """LOAD-BEARING: at the TTL the key is bcrypt-verified again. Fails if expiry is ignored."""
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    clock.now += _TTL
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(checkpw_calls) == 2


def test_hits_do_not_extend_the_ttl(device, clock, checkpw_calls, refresher):
    """Expiry is absolute from verification: hits alone never move it."""
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    for _ in range(4):
        clock.now += _TTL / 10
        _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(checkpw_calls) == 1
    assert refresher.jobs == []  # still under half the TTL: no re-verify claimed
    clock.now += _TTL
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(checkpw_calls) == 2


def test_unrun_refresh_does_not_extend_the_ttl(device, clock, checkpw_calls, refresher):
    """
    LOAD-BEARING: claiming a refresh renews nothing; only a finished, passing
    bcrypt does. Fails if the claim itself (or the hit) moves the expiry.
    """
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    clock.now += _TTL * 0.75
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(refresher.jobs) == 1
    clock.now += _TTL * 0.25
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(checkpw_calls) == 2  # expired: inline bcrypt again


# ── refresh-ahead ────────────────────────────────────────────────────────────


def test_refresh_ahead_keeps_bcrypt_off_the_request(device, clock, checkpw_calls, refresher):
    """
    A steadily sending device pays bcrypt inline once: past half the TTL a hit
    queues a re-verify, and the renewed entry outlives the original expiry.
    """
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    inline = background = 0
    for _ in range(10):  # 3 TTLs of one request every 0.3 TTL
        clock.now += _TTL * 0.3
        before = len(checkpw_calls)
        _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
        inline += len(checkpw_calls) - before
        background += refresher.run_all()
    assert inline == 0
    assert background == 5  # one re-verify every other request (0.6 TTL apart)
    assert len(checkpw_calls) == 1 + background


def test_refresh_is_claimed_once_per_entry(device, clock, refresher):
    """Concurrent hits past the half-life queue one re-verify, not one each."""
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    clock.now += _TTL * 0.6
    for _ in range(5):
        _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(refresher.jobs) == 1
    refresher.run_all()
    clock.now += _TTL * 0.1  # fresh entry: under half its TTL again
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert refresher.jobs == []


def test_wrong_key_cannot_claim_a_refresh(device, clock, refresher, checkpw_calls):
    """A forged request on a cached device never queues background bcrypt work."""
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    clock.now += _TTL * 0.6
    _assert_401(device, _WRONG_KEY)
    assert refresher.jobs == []
    assert not api_ingestion.device_credential_cache.claim_refresh(
        device, _WRONG_KEY, db_module.get_device(device)["api_key_hash"]
    )


def test_failed_refresh_does_not_renew(device, clock, checkpw_calls, refresher, monkeypatch):
    """
    LOAD-BEARING: a re-verify that does not pass leaves the old expiry in place.
    Fails if finish_refresh renews regardless of the bcrypt verdict.
    """
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    clock.now += _TTL * 0.6
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    monkeypatch.setattr(api_ingestion.bcrypt, "checkpw", lambda pw, h: False)
    assert refresher.run_all() == 1
    clock.now += _TTL * 0.4
    _assert_401(device, _CORRECT_KEY)  # expired, and the (patched) bcrypt says no


def test_crashed_refresh_releases_the_claim(device, clock, refresher, monkeypatch):
    """An exception in the re-verify renews nothing and lets a later hit retry."""
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    clock.now += _TTL * 0.6
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)

    def boom(pw, h):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(api_ingestion.bcrypt, "checkpw", boom)
    refresher.run_all()
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(refresher.jobs) == 1


def test_invalidate_during_refresh_is_not_undone(device, clock, refresher, checkpw_calls):
    """
    LOAD-BEARING: forgetting a device while its re-verify runs wins. Fails if
    finish_refresh stores the entry without checking the claim still stands.
    """
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    clock.now += _TTL * 0.6
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    api_ingestion.device_credential_cache.invalidate(device)
    refresher.run_all()
    assert len(api_ingestion.device_credential_cache) == 0
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(checkpw_calls) == 3  # first, the refresh, and inline again


def test_rekeyed_device_mid_refresh_rejects_old_key(device, clock, refresher):
    """A refresh that finishes after a re-key cannot make the old key pass."""
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    clock.now += _TTL * 0.6
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    _set_hash(device, _hash("test-rotated-cache-key-789"))
    refresher.run_all()  # renews the entry for the OLD hash only
    _assert_401(device, _CORRECT_KEY)


def test_ttl_zero_disables_the_cache(device, monkeypatch, checkpw_calls):
    monkeypatch.setattr(
        api_ingestion, "device_credential_cache", VerifiedCredentialCache(ttl_seconds=0, max_entries=100)
    )
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(checkpw_calls) == 2
    assert len(api_ingestion.device_credential_cache) == 0


# ── revoked ──────────────────────────────────────────────────────────────────


def test_deleted_device_rejected_despite_cache(device, clock):
    """
    LOAD-BEARING: deleting a device revokes it at once, not after the TTL.
    Fails if a hit returns before the device row is read.
    """
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    _delete(device)
    _assert_401(device, _CORRECT_KEY, detail="Unknown device.")


def test_rekeyed_device_rejects_old_key_despite_cache(device, clock, checkpw_calls):
    """
    LOAD-BEARING: replacing the stored hash revokes the old key at once.
    Fails if the entry is not bound to the hash it was verified against.
    """
    new_key = "test-rotated-cache-key-456"
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    _set_hash(device, _hash(new_key))
    _assert_401(device, _CORRECT_KEY)
    assert _authenticate_device(x_device_id=device, x_api_key=new_key)["id"] == device


def test_cleared_credential_rejected_despite_cache(device, clock):
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    _set_hash(device, "")
    _assert_401(device, _CORRECT_KEY, detail="Device has no credential set.")


def test_legacy_plaintext_rows_are_not_cached(device, clock):
    """Only the bcrypt path is cached; legacy rows keep the constant-time compare."""
    _set_hash(device, _CORRECT_KEY)
    _authenticate_device(x_device_id=device, x_api_key=_CORRECT_KEY)
    assert len(api_ingestion.device_credential_cache) == 0


# ── boundedness / storage ────────────────────────────────────────────────────


def test_cache_is_bounded_lru():
    """LOAD-BEARING: never more than max_entries; least recently used goes first."""
    c = _Clock()
    cache = VerifiedCredentialCache(ttl_seconds=_TTL, max_entries=3, clock=c)
    for i in range(3):
        cache.remember(f"dev-{i}", f"key-{i}", "$2b$hash")
    assert cache.is_verified("dev-0", "key-0", "$2b$hash")  # dev-0 now most recent
    for i in range(3, 10):
        cache.remember(f"dev-{i}", f"key-{i}", "$2b$hash")
        assert len(cache) <= 3
    assert len(cache) == 3
    assert not cache.is_verified("dev-0", "key-0", "$2b$hash")
    assert cache.is_verified("dev-9", "key-9", "$2b$hash")


def test_cache_never_holds_the_plaintext_key():
    """Entries carry an HMAC fingerprint under a per-process secret, not the key."""
    cache = VerifiedCredentialCache(ttl_seconds=_TTL, max_entries=10)
    cache.remember(_DEVICE_ID, _CORRECT_KEY, "$2b$hash")
    (entry,) = cache._entries.values()
    flat = repr(entry).encode("utf-8") + b"".join(
        f if isinstance(f, bytes) else str(f).encode("utf-8") for f in entry
    )
    assert _CORRECT_KEY.encode("utf-8") not in flat
    assert len(entry.fingerprint) == 32
    # A second process (another secret) produces a different fingerprint.
    other = VerifiedCredentialCache(ttl_seconds=_TTL, max_entries=10)
    assert other._fingerprint(_CORRECT_KEY) != entry.fingerprint


def test_concurrent_auth_is_consistent(device, clock):
    """Threadpool callers: concurrent right and wrong keys never cross over."""
    errors = []

    def worker(key: str, expect_ok: bool) -> None:
        for _ in range(20):
            try:
                _authenticate_device(x_device_id=device, x_api_key=key)
                if not expect_ok:
                    errors.append("wrong key accepted")
            except HTTPException as exc:
                if expect_ok or exc.status_code != 401:
                    errors.append(f"unexpected {exc.status_code}")

    threads = [threading.Thread(target=worker, args=(_CORRECT_KEY, True)) for _ in range(4)]
    threads += [threading.Thread(target=worker, args=(_WRONG_KEY, False)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
