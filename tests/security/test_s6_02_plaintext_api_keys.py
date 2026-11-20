"""
LSADRA security regression — §6 #02: Plaintext API keys at device registration.

Attacker story: a DB read or backup leak exposes usable device API keys,
because device registration once stored the raw key directly as
``api_key_hash`` (``api_key_hash = api_key  # TODO: bcrypt``). The fix
(dd3eb12) hashes the key with bcrypt before persisting, so a leaked
``devices`` row is no longer a working credential.

These tests exercise POST /api/devices/register end-to-end and assert the
stored key material is a bcrypt hash — not the raw key. On the pre-fix code
path the stored value equals the raw key and does not start with ``$2``,
which fails these assertions.
"""

import pytest

from tests.fixtures import setup_test_db


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    """Set up a temporary test database for each test."""
    setup_test_db(tmp_path)


@pytest.fixture
def client():
    """Create a FastAPI test client."""
    from fastapi.testclient import TestClient
    from server import app

    return TestClient(app)


def _register(client):
    """Mint a single-use token and register one device; return the response JSON."""
    from lsadra.onboarding.token_manager import generate_token
    from lsadra.storage.database import create_user

    # registration_tokens.user_id is a FK to users and foreign keys are
    # enforced (PRAGMA foreign_keys=ON), so the initiating user must exist
    # before a registration token can be minted. Synthetic user only.
    create_user("test-user-1", "test-user-1", "synthetic-not-a-real-hash", "ANALYST")

    token = generate_token("test-user-1")
    resp = client.post(
        "/api/devices/register",
        json={"token": token, "hostname": "test-host", "os_type": "linux"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestPlaintextApiKeyRegression:
    """§6 #02 — registration must store a bcrypt hash, never the raw key."""

    def test_stored_key_is_bcrypt_hash_not_plaintext(self, client):
        from lsadra.storage.database import get_device

        data = _register(client)
        device_id = data["device_id"]
        raw_api_key = data["api_key"]

        stored = get_device(device_id)
        assert stored is not None
        stored_hash = stored["api_key_hash"]

        # Core regression: the DB must NOT hold the raw key (leak-usable).
        assert stored_hash != raw_api_key
        # bcrypt marker — pre-fix plaintext (a token_urlsafe string) never starts with "$2".
        assert stored_hash.startswith("$2")

    def test_raw_key_verifies_against_stored_hash(self, client):
        import bcrypt
        from lsadra.storage.database import get_device

        data = _register(client)
        raw_api_key = data["api_key"]
        stored_hash = get_device(data["device_id"])["api_key_hash"]

        # The raw key returned once must verify against the stored hash...
        assert bcrypt.checkpw(raw_api_key.encode("utf-8"), stored_hash.encode("utf-8")) is True
        # ...and a wrong key must not.
        assert bcrypt.checkpw(b"test-secret-abc123", stored_hash.encode("utf-8")) is False

    def test_api_key_returned_once_and_is_urlsafe(self, client):
        # The registration response is the only place the raw key appears.
        data = _register(client)
        assert isinstance(data["api_key"], str)
        assert len(data["api_key"]) >= 32
        # Response advertises where to send events but never re-exposes the hash.
        assert "api_key_hash" not in data
        assert data["collector_url"] == "/api/events/batch"
