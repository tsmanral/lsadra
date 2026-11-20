"""
LSADRA V3 — Agent behavior tests.

Tests for the agent simulator configuration generation and
heartbeat behavior.
"""

import pytest
from tests.fixtures import MockLogEvent, setup_test_db


@pytest.fixture(autouse=True)
def _test_db(tmp_path):
    setup_test_db(tmp_path)


class TestAgentConfig:
    """Tests for agent configuration handling."""

    def test_mock_event_to_dict(self):
        event = MockLogEvent()
        d = event.to_dict()
        assert d["device_id"] == "test-device-001"
        assert d["event_type"] == "auth_failure"
        assert d["source_ip"] == "192.168.1.100"

    def test_mock_event_customization(self):
        event = MockLogEvent(
            source_ip="10.0.0.1",
            event_type="auth_success",
            effective_username="root",
        )
        d = event.to_dict()
        assert d["source_ip"] == "10.0.0.1"
        assert d["event_type"] == "auth_success"
        assert d["effective_username"] == "root"


class TestDatabaseOperations:
    """Tests for database CRUD operations used by the agent."""

    def test_insert_and_retrieve_event(self):
        from lsadra.storage.database import (
            create_user,
            create_device,
            insert_event,
            get_events_since,
        )

        # Create parent records to satisfy FK constraints
        create_user("test-user-001", "testuser", "hash", "ANALYST")
        create_device("test-device-001", "test-user-001", "test-host", "linux", "apikey")

        event = MockLogEvent().to_dict()
        row_id = insert_event(event)
        assert row_id > 0

        events = get_events_since("test-device-001", after_id=0)
        assert len(events) >= 1
        assert events[0]["source_ip"] == "192.168.1.100"

    def test_device_lifecycle(self):
        from lsadra.storage.database import (
            create_user,
            create_device,
            get_device,
            update_device_status,
            increment_device_event_count,
        )

        create_user("u1", "testuser", "hash", "ANALYST")
        create_device("d1", "u1", "test-host", "linux", "apikey")

        device = get_device("d1")
        assert device is not None
        assert device["status"] == "BASELINING"
        assert device["event_count"] == 0

        new_count = increment_device_event_count("d1", 50)
        assert new_count == 50

        update_device_status("d1", "ONLINE")
        device = get_device("d1")
        assert device["status"] == "ONLINE"

    def test_heartbeat_storage(self):
        from lsadra.storage.database import (
            create_user,
            create_device,
            insert_heartbeat,
            get_latest_heartbeat,
        )

        create_user("u1", "testuser", "hash", "ANALYST")
        create_device("d1", "u1", "test-host", "linux", "apikey")

        insert_heartbeat("d1", cpu_pct=45.0, mem_pct=60.0, agent_version="3.0.0")
        hb = get_latest_heartbeat("d1")
        assert hb is not None
        assert hb["cpu_pct"] == 45.0
        assert hb["agent_version"] == "3.0.0"

    def test_incident_creation_and_update(self):
        from lsadra.storage.database import (
            create_user,
            create_device,
            create_incident,
            get_incident,
            update_incident_status,
            assign_incident,
        )

        # Create parent records for FK constraints
        create_user("u1", "testuser", "hash", "ANALYST")
        create_device("d1", "u1", "test-host", "linux", "apikey")

        inc_id = create_incident(
            device_id="d1",
            source_ip="1.2.3.4",
            attack_type="Brute Force",
            severity_label="HIGH",
            first_seen="2026-03-15T14:00:00",
        )
        assert inc_id > 0

        inc = get_incident(inc_id)
        assert inc["status"] == "OPEN"

        update_incident_status(inc_id, "RESOLVED", "Fixed by admin")
        inc = get_incident(inc_id)
        assert inc["status"] == "RESOLVED"
