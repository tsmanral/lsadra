"""
§6 #7 — /ws/alerts must authenticate at the handshake.

Attacker story: a live alert feed that accepts any connection hands every
tenant's alerts (device ids, source IPs, threat types) to anyone who can reach
the port, and a token checked only after accept still gives the attacker an
open socket.

Secure behavior pinned here: a connection without a valid JWT for a dashboard
role is closed with 1008 before it is accepted (missing, tampered, wrong-secret,
expired or role-less tokens, a token only in the query string, plain ws://
while TLS is required). A valid token is accepted from the Authorization header
or the ``bearer`` subprotocol; a non-admin receives only their own alerts; the
socket closes with 1008 when the token expires; a client that stops reading is
closed with 1013. SYNTHETIC data only.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt
import numpy as np
import pytest
from starlette.websockets import WebSocketDisconnect

from lsadra.auth import create_access_token
from lsadra.config import JWT_SECRET, TOKEN_ALGORITHM
from lsadra.ui import alert_stream
from lsadra.ui.alert_stream import (
    WS_POLICY_VIOLATION,
    WS_TRY_AGAIN_LATER,
    AlertHub,
    alert_hub,
    alert_message,
)

PATH = "/ws/alerts"


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from server import app
    return TestClient(app)


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _anomaly(owner: str, anomaly_id: int) -> dict:
    return {
        "anomaly_id": anomaly_id, "incident_id": 7, "event_id": 41,
        "device_id": "dev-demo-01", "user_id": owner, "source_ip": "203.0.113.9",
        "severity_label": "HIGH", "severity_score": 0.82,
        "threat_type": "Brute Force Attack", "mitre_technique": "T1110.001",
        "created_at": "2026-03-15T14:30:00Z", "narrative": "not streamed",
    }


def _expect_rejected(client, **kwargs) -> None:
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(PATH, **kwargs) as ws:
            ws.receive_json()
    assert exc.value.code == WS_POLICY_VIOLATION


def _wait_for_subscribers(n: int) -> None:
    deadline = time.time() + 5
    while alert_hub.subscriber_count < n:
        assert time.time() < deadline, "subscriber never registered"
        time.sleep(0.01)


# ── rejected at the handshake ─────────────────────────────────────────────


def test_no_credentials_rejected(client):
    _expect_rejected(client)


def test_tampered_token_rejected(client):
    head, body, sig = create_access_token("u-1", "alice.demo", "ANALYST").split(".")
    _expect_rejected(client, headers=_bearer(f"{head}.{body}.{sig[::-1]}"))


def test_wrong_secret_rejected(client):
    exp = datetime.now(timezone.utc) + timedelta(minutes=5)
    forged = jwt.encode({"sub": "u-1", "role": "ADMIN", "exp": exp}, "x" * 48)
    _expect_rejected(client, headers=_bearer(forged))


def test_expired_token_rejected(client):
    token = create_access_token("u-1", "alice.demo", "ANALYST", expires_minutes=-1)
    _expect_rejected(client, headers=_bearer(token))
    _expect_rejected(client, subprotocols=["bearer", token])


def test_unknown_role_rejected(client):
    _expect_rejected(client, headers=_bearer(create_access_token("u-1", "x.demo", "AGENT")))


def test_token_in_query_string_ignored(client):
    token = create_access_token("u-1", "alice.demo", "ANALYST")
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"{PATH}?token={token}") as ws:
            ws.receive_json()
    assert exc.value.code == WS_POLICY_VIOLATION


def test_plain_ws_rejected_when_tls_required(client):
    token = create_access_token("u-1", "alice.demo", "ANALYST")
    with patch.object(alert_stream.config, "REQUIRE_TLS", True):
        _expect_rejected(client, headers=_bearer(token))


# ── accepted ──────────────────────────────────────────────────────────────


def test_header_token_accepted(client):
    with client.websocket_connect(PATH, headers=_bearer(
        create_access_token("u-1", "alice.demo", "VIEWER")
    )) as ws:
        ready = ws.receive_json()
    assert ready["type"] == "ready"
    assert ready["expires_at"] > time.time()


def test_subprotocol_token_accepted(client):
    token = create_access_token("u-1", "alice.demo", "ANALYST")
    with client.websocket_connect(PATH, subprotocols=["bearer", token]) as ws:
        assert ws.accepted_subprotocol == "bearer"
        assert ws.receive_json()["type"] == "ready"


def test_wss_accepted_when_tls_required(client):
    token = create_access_token("u-1", "alice.demo", "ANALYST")
    with patch.object(alert_stream.config, "REQUIRE_TLS", True):
        with client.websocket_connect(f"wss://testserver{PATH}", headers=_bearer(token)) as ws:
            assert ws.receive_json()["type"] == "ready"


def test_forwarded_proto_only_trusted_from_configured_proxy(client):
    token = create_access_token("u-1", "alice.demo", "ANALYST")
    headers = {**_bearer(token), "X-Forwarded-Proto": "https"}
    with patch.object(alert_stream.config, "REQUIRE_TLS", True):
        _expect_rejected(client, headers=dict(headers))  # spoofed by the client itself
        with patch.object(alert_stream.config, "TRUSTED_PROXY_IPS", ["testclient"]):
            with client.websocket_connect(PATH, headers=dict(headers)) as ws:
                assert ws.receive_json()["type"] == "ready"


# ── what an open socket receives ──────────────────────────────────────────


def test_non_admin_receives_only_own_alerts(client):
    token = create_access_token("u-alice", "alice.demo", "ANALYST")
    with client.websocket_connect(PATH, headers=_bearer(token)) as ws:
        ws.receive_json()
        _wait_for_subscribers(1)
        # Published from this (non-loop) thread, as the detection worker does.
        alert_hub.publish(_anomaly("u-bob", 1))
        alert_hub.publish(_anomaly("u-alice", 2))
        alert = ws.receive_json()
    assert alert["type"] == "alert"
    assert alert["anomaly_id"] == 2
    assert "narrative" not in alert and "user_id" not in alert


def test_admin_receives_every_alert(client):
    token = create_access_token("u-admin", "admin.demo", "ADMIN")
    with client.websocket_connect(PATH, headers=_bearer(token)) as ws:
        ws.receive_json()
        _wait_for_subscribers(1)
        alert_hub.publish(_anomaly("u-bob", 1))
        alert_hub.publish(_anomaly("u-alice", 2))
        assert [ws.receive_json()["anomaly_id"] for _ in range(2)] == [1, 2]


def test_socket_closes_when_token_expires(client):
    exp = datetime.now(timezone.utc) + timedelta(seconds=2)
    token = jwt.encode(
        {"sub": "u-1", "role": "ANALYST", "exp": exp}, JWT_SECRET, algorithm=TOKEN_ALGORITHM
    )
    with client.websocket_connect(PATH, headers=_bearer(token)) as ws:
        assert ws.receive_json()["type"] == "ready"
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
    assert exc.value.code == WS_POLICY_VIOLATION


def test_disconnect_unsubscribes(client):
    token = create_access_token("u-1", "alice.demo", "ANALYST")
    with client.websocket_connect(PATH, headers=_bearer(token)) as ws:
        ws.receive_json()
        _wait_for_subscribers(1)
    deadline = time.time() + 5
    while alert_hub.subscriber_count:
        assert time.time() < deadline
        time.sleep(0.01)


# ── hub ───────────────────────────────────────────────────────────────────


def test_slow_client_gets_overflow_and_is_dropped():
    async def scenario():
        hub = AlertHub(queue_size=2)
        sub = hub.subscribe("u-1", is_admin=False)
        for i in range(3):
            hub.publish(_anomaly("u-1", i))
        await asyncio.sleep(0)  # let the call_soon_threadsafe deliveries run
        assert hub.subscriber_count == 0
        assert sub.queue.qsize() == 1
        assert sub.queue.get_nowait() is alert_stream._OVERFLOW

    asyncio.run(scenario())


def test_overflow_closes_socket_with_1013(client):
    token = create_access_token("u-1", "alice.demo", "ANALYST")
    with client.websocket_connect(PATH, headers=_bearer(token)) as ws:
        ws.receive_json()
        _wait_for_subscribers(1)
        (sub,) = list(alert_hub._subs)
        # Fill the queue past its bound on the subscriber's loop in one step,
        # so the sender cannot drain it in between.
        def flood():
            for i in range(alert_hub.queue_size + 1):
                alert_hub._deliver(sub, alert_message(_anomaly("u-1", i)))
        sub.loop.call_soon_threadsafe(flood)
        with pytest.raises(WebSocketDisconnect) as exc:
            while True:
                ws.receive_json()
    assert exc.value.code == WS_TRY_AGAIN_LATER


def test_publish_never_raises():
    alert_hub.publish({"user_id": "u-1", "severity_score": "not-a-number"})
    alert_hub.publish(None)  # type: ignore[arg-type]


def test_alert_message_is_json_safe_for_numpy_values():
    raw = _anomaly("u-1", 3)
    raw.update(anomaly_id=np.int64(3), severity_score=np.float64(0.9))
    message = alert_message(raw)
    assert json.loads(json.dumps(message))["severity_score"] == pytest.approx(0.9)
