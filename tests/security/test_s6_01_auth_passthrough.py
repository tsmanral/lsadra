"""
LSADRA security regression — §6 #01: Auth pass-through in device ingestion.

Attacker story: an attacker who knows a device_id but not its API key could
ingest forged events, because the pre-fix `_authenticate_device` only
logged-and-continued on a key mismatch (and auto-passed when the stored hash
was empty). This test pins the fixed behavior: a bad or absent credential must
yield 401 and MUST NOT reach ingestion.

Fix commit dd3eb12 — `lsadra.ingestion.api_ingestion._authenticate_device`.

SYNTHETIC data only. No real credentials or keys.
"""

import pytest
from unittest.mock import patch

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


# Minimal valid EventBatch body (event contract v1): only schema_version,
# timestamp and event_type are required.
_VALID_BATCH = {
    "events": [
        {"schema_version": "1", "timestamp": "2026-03-15T14:30:00Z", "event_type": "auth_failure"},
    ]
}


class TestAuthPassthrough:
    """§6 #01 — device ingestion must reject forged / empty credentials."""

    def test_mismatched_api_key_rejected_and_no_ingestion(self, client):
        """
        Wrong X-API-Key => 401 'Invalid API key.' and store_batch_and_touch
        is never called.

        Pre-fix code logged-and-continued on mismatch, so the batch would be
        ingested with a 200 — this assertion would fail there.
        """
        from lsadra.storage.database import create_user, create_device

        create_user("u1", "tester", "hash", "ANALYST")
        # Non-bcrypt stored hash => constant-time hmac comparison path.
        create_device("test-device-001", "u1", "test-host", "linux", "test-secret-abc123")

        with patch(
            "lsadra.ingestion.api_ingestion.store_batch_and_touch"
        ) as mock_ins:
            response = client.post(
                "/api/events/batch",
                json=_VALID_BATCH,
                headers={
                    "X-Device-Id": "test-device-001",
                    "X-API-Key": "wrong-key-000",
                },
            )

        assert response.status_code == 401, response.text
        assert response.json()["detail"] == "Invalid API key."
        # A 401 raised by the Depends guard must short-circuit the handler body.
        mock_ins.assert_not_called()

    def test_empty_stored_hash_never_authenticates(self, client):
        """
        Device with a blank stored api_key_hash => 401 'Device has no
        credential set.' for ANY presented key, and no ingestion.

        Pre-fix code treated an empty stored hash as an auto-pass, letting any
        key through — this assertion would fail there.
        """
        from lsadra.storage.database import create_user, create_device

        create_user("u2", "tester2", "hash", "ANALYST")
        create_device("test-device-002", "u2", "test-host", "linux", "")

        with patch(
            "lsadra.ingestion.api_ingestion.store_batch_and_touch"
        ) as mock_ins:
            response = client.post(
                "/api/events/batch",
                json=_VALID_BATCH,
                headers={
                    "X-Device-Id": "test-device-002",
                    "X-API-Key": "anything-goes-xyz",
                },
            )

        assert response.status_code == 401, response.text
        assert response.json()["detail"] == "Device has no credential set."
        mock_ins.assert_not_called()
