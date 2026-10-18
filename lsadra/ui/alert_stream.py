"""
Live alert stream: the authenticated ``/ws/alerts`` WebSocket (§6 #7).

The socket authenticates at the handshake, before it is accepted. Nothing is
sent to a client whose JWT has not verified, and an unauthenticated client
never gets an open connection.

Handshake
    The token is the same JWT the dashboard holds for REST calls
    (``POST /api/auth/login``). Browsers cannot set headers on a WebSocket, so
    they pass it as a subprotocol, ``new WebSocket(url, ["bearer", token])``,
    and the server answers with the ``bearer`` subprotocol. Other clients may
    send ``Authorization: Bearer <token>`` instead. Tokens in the query string
    are not read: URLs end up in proxy and access logs.

Close codes
    ``1008`` (policy violation): missing, invalid or expired token, a role
    outside ADMIN/ANALYST/VIEWER, or plain ``ws://`` while TLS is required.
    Before the handshake completes this reaches the client as an HTTP 403; on
    an open socket (the token expired) it is a normal close frame.
    ``1013`` (try again later): the client stopped reading and its buffer of
    ``WS_ALERT_QUEUE_SIZE`` alerts filled up. It should reconnect and backfill
    from ``GET /api/dashboard/anomalies``.

Scope
    The same rule as the REST endpoints: an ADMIN receives every alert, anyone
    else only alerts whose ``user_id`` is their own.

Messages
    One ``{"type": "ready", "expires_at": <unix seconds>}`` after accept, then
    one ``{"type": "alert", ...}`` per persisted anomaly. The connection is
    closed with 1008 when the token expires; the client reconnects with a fresh
    one. Details (narrative, SHAP values) stay behind the REST API.

Detection runs on its own worker thread, so :meth:`AlertHub.publish` is
thread-safe and never blocks: it hands the alert to each subscriber's event
loop with ``call_soon_threadsafe``. Origin is not checked: the socket is
authenticated by a bearer token, never by cookies, so a cross-site page has
nothing to ride on.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from contextlib import suppress
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, HTTPException, WebSocket

from lsadra import config
from lsadra.auth import decode_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["alerts"])

WS_POLICY_VIOLATION = 1008
WS_TRY_AGAIN_LATER = 1013
BEARER_SUBPROTOCOL = "bearer"
STREAM_ROLES = ("ADMIN", "ANALYST", "VIEWER")  # same as GET /api/dashboard/anomalies

_OVERFLOW = object()  # queued in place of the backlog when a client falls behind


# ── Alert hub ────────────────────────────────────────────────────────────


class Subscription:
    """One connected client: its scope, its loop and its bounded queue."""

    def __init__(self, user_id: str, is_admin: bool, maxsize: int) -> None:
        self.user_id = user_id
        self.is_admin = is_admin
        self.loop = asyncio.get_running_loop()
        self.queue: "asyncio.Queue[Any]" = asyncio.Queue(maxsize)

    def wants(self, owner: str) -> bool:
        return self.is_admin or owner == self.user_id


class AlertHub:
    """Fans persisted anomalies out to the connected ``/ws/alerts`` clients."""

    def __init__(self, queue_size: int) -> None:
        self.queue_size = queue_size
        self._subs: Set[Subscription] = set()
        self._lock = threading.Lock()  # publish() runs on the detection thread

    def subscribe(self, user_id: str, is_admin: bool) -> Subscription:
        """Register a client (call on its event loop)."""
        sub = Subscription(user_id, is_admin, self.queue_size)
        with self._lock:
            self._subs.add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            self._subs.discard(sub)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    def publish(self, anomaly: Dict[str, Any]) -> None:
        """Queue *anomaly* for every subscriber allowed to see it (any thread).

        Never raises and never blocks: a failure here must not cost detection
        its run.
        """
        try:
            owner = str(anomaly.get("user_id") or "")
            with self._lock:
                targets = [s for s in self._subs if s.wants(owner)]
            if not targets:
                return
            message = alert_message(anomaly)
            for sub in targets:
                with suppress(RuntimeError):  # that client's loop already closed
                    sub.loop.call_soon_threadsafe(self._deliver, sub, message)
        except Exception:
            logger.exception("Alert stream publish failed; detection is unaffected.")

    def _deliver(self, sub: Subscription, message: Dict[str, Any]) -> None:
        """Runs on the subscriber's loop."""
        try:
            sub.queue.put_nowait(message)
        except asyncio.QueueFull:
            # The client is not reading. Drop its backlog, tell it to resync,
            # and stop feeding it.
            self.unsubscribe(sub)
            while not sub.queue.empty():
                sub.queue.get_nowait()
            sub.queue.put_nowait(_OVERFLOW)


alert_hub = AlertHub(config.WS_ALERT_QUEUE_SIZE)


def _opt(value: Any, cast) -> Any:
    return None if value is None else cast(value)


def alert_message(anomaly: Dict[str, Any]) -> Dict[str, Any]:
    """JSON-safe summary of a persisted anomaly (detection values may be numpy)."""
    return {
        "type": "alert",
        "anomaly_id": _opt(anomaly.get("anomaly_id"), int),
        "incident_id": _opt(anomaly.get("incident_id"), int),
        "event_id": _opt(anomaly.get("event_id"), int),
        "device_id": str(anomaly.get("device_id") or ""),
        "source_ip": str(anomaly.get("source_ip") or ""),
        "severity_label": str(anomaly.get("severity_label") or ""),
        "severity_score": _opt(anomaly.get("severity_score"), float),
        "threat_type": str(anomaly.get("threat_type") or ""),
        "mitre_technique": str(anomaly.get("mitre_technique") or ""),
        "created_at": str(anomaly.get("created_at") or ""),
    }


# ── Handshake ────────────────────────────────────────────────────────────


def _is_tls(websocket: WebSocket) -> bool:
    """Same rule as TLSEnforcementMiddleware, which only sees HTTP requests."""
    scheme = websocket.url.scheme
    client_ip = websocket.client.host if websocket.client else None
    if client_ip and client_ip in config.TRUSTED_PROXY_IPS:
        scheme = websocket.headers.get("x-forwarded-proto", scheme)
    return scheme in ("wss", "https")


def _handshake_token(websocket: WebSocket) -> Tuple[Optional[str], Optional[str]]:
    """``(token, subprotocol to accept with)`` from the handshake, if any."""
    offered: List[str] = list(websocket.scope.get("subprotocols") or [])
    if len(offered) == 2 and offered[0].lower() == BEARER_SUBPROTOCOL and offered[1]:
        return offered[1], offered[0]
    scheme, _, credentials = websocket.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and credentials.strip():
        return credentials.strip(), None
    return None, None


def authenticate_handshake(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """The caller's identity if *token* is a valid JWT for a streaming role."""
    if not token:
        return None
    try:
        payload = decode_token(token)
    except HTTPException:
        return None
    role = payload.get("role", "VIEWER")
    if role not in STREAM_ROLES:
        return None
    return {"user_id": payload["sub"], "role": role, "exp": float(payload["exp"])}


async def _reject(websocket: WebSocket, reason: str) -> None:
    client = websocket.client.host if websocket.client else "unknown"
    logger.warning("Rejected /ws/alerts handshake from %s: %s", client, reason)
    await websocket.close(code=WS_POLICY_VIOLATION, reason=reason)


# ── Endpoint ─────────────────────────────────────────────────────────────


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    if config.REQUIRE_TLS and not _is_tls(websocket):
        await _reject(websocket, "TLS is required.")
        return
    token, subprotocol = _handshake_token(websocket)
    if token is None:
        await _reject(websocket, "Missing authentication credentials.")
        return
    user = authenticate_handshake(token)
    if user is None:
        await _reject(websocket, "Invalid or expired token.")
        return

    await websocket.accept(subprotocol=subprotocol)
    sub = alert_hub.subscribe(user["user_id"], user["role"] == "ADMIN")
    sender = asyncio.create_task(_send_alerts(websocket, sub, user["exp"]))
    receiver = asyncio.create_task(_drain_client(websocket))
    try:
        await asyncio.wait({sender, receiver}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        alert_hub.unsubscribe(sub)
        for task in (sender, receiver):
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await task


async def _send_alerts(websocket: WebSocket, sub: Subscription, expires_at: float) -> None:
    await websocket.send_json({"type": "ready", "expires_at": int(expires_at)})
    while True:
        remaining = expires_at - time.time()
        if remaining <= 0:
            await websocket.close(code=WS_POLICY_VIOLATION, reason="Token expired.")
            return
        try:
            message = await asyncio.wait_for(sub.queue.get(), timeout=remaining)
        except asyncio.TimeoutError:
            continue
        if message is _OVERFLOW:
            await websocket.close(
                code=WS_TRY_AGAIN_LATER,
                reason="Alert backlog exceeded; reconnect and backfill.",
            )
            return
        await websocket.send_json(message)


async def _drain_client(websocket: WebSocket) -> None:
    """Returns when the client goes away. The stream is one-way, so client
    messages are read and discarded."""
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
