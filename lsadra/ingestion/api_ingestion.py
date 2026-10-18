"""
LSADRA V3+V4 — HTTPS ingestion API.

FastAPI router that accepts:
  V3: authenticated JSON event batches from endpoint agents (unchanged)
  V4: raw log lines from any supported source via IngestionManager

[V4 ENHANCEMENT — gap: multi-source ingestion]
"""

import hmac
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Literal, Optional

import bcrypt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool

from lsadra.config import (
    BENCH_SKIP_DETECTION,
    DETECTION_QUEUE_RETRY_AFTER_SECONDS,
    MAX_ATTRIBUTE_KEYS,
    MAX_ATTRIBUTE_VALUE_LENGTH,
    MAX_ATTRIBUTES_BYTES,
    MAX_EVENT_TYPE_LENGTH,
    MAX_EVENTS_PER_BATCH,
    MAX_HOSTNAME_LENGTH,
    MAX_RAW_MESSAGE_LENGTH,
    MAX_SOURCE_IP_LENGTH,
    MAX_USERNAME_LENGTH,
    RATE_LIMIT_EVENTS_PER_MIN,
    RATE_LIMIT_MAX_KEYS,
)
from lsadra.detection.detection_worker import detection_queue
from lsadra.ratelimit import SlidingWindowRateLimiter
from lsadra.storage.database import get_device, store_batch_and_touch

logger = logging.getLogger(__name__)


class _ContractRoute(APIRoute):
    """
    Ingestion route whose 422s never echo the rejected input.

    FastAPI's default 422 body includes each error's ``input``, serialized by a
    recursive encoder: a deeply nested rejected value turns the 422 into a 500
    (RecursionError), and large values would be reflected back verbatim. Errors
    keep ``type``, ``loc`` and ``msg`` — enough to name the offending field.
    """

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def contract_handler(request: Request) -> Response:
            try:
                return await handler(request)
            except RequestValidationError as exc:
                errors = [
                    {"type": e.get("type"), "loc": list(e.get("loc", ())), "msg": str(e.get("msg", ""))}
                    for e in exc.errors()
                ]
                raise RequestValidationError(errors) from None

        return contract_handler


router = APIRouter(tags=["ingestion"], route_class=_ContractRoute)

# ── Pydantic models ───────────────────────────────────────────────────────
# Event contract v1 (frozen): docs/contracts/event-schema.v1.json is the source
# of truth; NormalizedEvent mirrors it and tests/test_contracts.py fails if the
# two drift. Every violation is a 422 naming the offending field — the batch
# is rejected whole before anything is written.

SCHEMA_VERSION = "1"

# RFC 3339 date-time with a mandatory offset. Seconds 00-59 (no leap second:
# Python datetimes cannot represent :60). Identical to the schema's `pattern`.
RFC3339_PATTERN = (
    r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?"
    r"([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$"
)
_RFC3339_RE = re.compile(RFC3339_PATTERN)

# Parser hints accepted by POST /api/events/raw (IngestionManager._HINT_MAP).
SourceHint = Literal["ssh", "syslog", "windows", "network", "endpoint"]


def _compact_json(value: Any) -> str:
    """Serialize *value* the way the contract measures sizes (compact JSON)."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _source_ip_schema(schema: Dict[str, Any]) -> None:
    """Publish the ipv4|ipv6 formats that `_check_source_ip` enforces."""
    schema["anyOf"] = [
        {"type": "string", "maxLength": MAX_SOURCE_IP_LENGTH, "format": "ipv4"},
        {"type": "string", "maxLength": MAX_SOURCE_IP_LENGTH, "format": "ipv6"},
        {"type": "null"},
    ]


class NormalizedEvent(BaseModel):
    """
    One event sent by an endpoint agent — event contract v1.

    ``device_id`` and ``user_id`` are deliberately absent: they are
    server-assigned from the authenticated device (schema ``readOnly``), and
    ``extra="forbid"`` rejects an event that tries to supply them.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"]
    timestamp: AwareDatetime = Field(json_schema_extra={"pattern": RFC3339_PATTERN})
    host: str = Field(default="", max_length=MAX_HOSTNAME_LENGTH)
    effective_username: str = Field(default="", max_length=MAX_USERNAME_LENGTH)
    source_ip: Optional[str] = Field(
        default=None, max_length=MAX_SOURCE_IP_LENGTH, json_schema_extra=_source_ip_schema
    )
    event_type: str = Field(..., max_length=MAX_EVENT_TYPE_LENGTH)
    raw_message: str = Field(default="", max_length=MAX_RAW_MESSAGE_LENGTH)
    attributes: Dict[str, Any] = Field(
        default_factory=dict,
        max_length=MAX_ATTRIBUTE_KEYS,
        json_schema_extra={
            "additionalProperties": {"maxLength": MAX_ATTRIBUTE_VALUE_LENGTH},
            "x-lsadra-maxValueLength": MAX_ATTRIBUTE_VALUE_LENGTH,
            "x-lsadra-maxSerializedBytes": MAX_ATTRIBUTES_BYTES,
        },
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def _check_rfc3339(cls, value: Any) -> Any:
        # Before pydantic's lenient coercion, which would also accept epoch
        # numbers, a space separator and other non-RFC 3339 shapes.
        if not isinstance(value, str) or not _RFC3339_RE.fullmatch(value):
            raise ValueError(
                "timestamp must be an RFC 3339 date-time string with a UTC offset "
                "(Z or +/-HH:MM), e.g. 2026-01-15T02:01:12Z"
            )
        return value

    @field_validator("timestamp")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        try:
            return value.astimezone(timezone.utc)
        except OverflowError:  # e.g. 9999-12-31T23:59:59-23:59 — a 422, never a 500
            raise ValueError("timestamp is out of range once normalized to UTC") from None

    @field_validator("source_ip")
    @classmethod
    def _check_source_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        try:
            if "%" in value:  # IPv6 zone index: not part of RFC 4291 text form
                raise ValueError
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("source_ip must be an IPv4 or IPv6 address, or null") from None
        return value

    @field_validator("attributes")
    @classmethod
    def _check_attribute_sizes(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        try:
            for key, item in value.items():
                size = len(item) if isinstance(item, str) else len(_compact_json(item))
                if size > MAX_ATTRIBUTE_VALUE_LENGTH:
                    raise ValueError(
                        f"attributes[{key[:64]!r}] exceeds {MAX_ATTRIBUTE_VALUE_LENGTH} characters"
                    )
            total = len(_compact_json(value).encode("utf-8"))
        except (RecursionError, TypeError, OverflowError):
            # Pathologically nested / unserializable input must be a 422, never a 500.
            raise ValueError("attributes must be serializable JSON of bounded depth") from None
        if total > MAX_ATTRIBUTES_BYTES:
            raise ValueError(f"attributes exceeds {MAX_ATTRIBUTES_BYTES} bytes as compact JSON")
        return value


class EventBatch(BaseModel):
    """Wrapper for a batch of events from one device (≤ MAX_EVENTS_PER_BATCH)."""

    model_config = ConfigDict(extra="forbid")

    events: List[NormalizedEvent] = Field(..., max_length=MAX_EVENTS_PER_BATCH)


# ── Simple in-memory rate limiter ─────────────────────────────────────────

# Bounded LRU limiter — caps tracked device keys so dead/spoofed IDs cannot grow
# memory without bound (§6 #5).
_device_limiter = SlidingWindowRateLimiter(
    limit=RATE_LIMIT_EVENTS_PER_MIN, window_seconds=60, max_keys=RATE_LIMIT_MAX_KEYS
)


def _check_rate_limit(device_id: str) -> None:
    """Raise 429 if the device exceeds its per-minute event batch limit."""
    if not _device_limiter.allow(device_id, time.time()):
        raise HTTPException(status_code=429, detail="Rate limit exceeded for this device.")


# ── Auth dependency ───────────────────────────────────────────────────────


def _authenticate_device(x_device_id: str = Header(...), x_api_key: str = Header(...)) -> Dict[str, Any]:
    """
    Validate the device ID + API key sent in request headers.

    Returns the device row dict on success, raises 401 otherwise.
    Keys registered since hashing landed are bcrypt-verified; rows created
    before that stored the raw key and are compared in constant time.
    """
    device = get_device(x_device_id)
    if device is None:
        raise HTTPException(status_code=401, detail="Unknown device.")

    stored_hash = device.get("api_key_hash") or ""
    if not stored_hash:
        raise HTTPException(status_code=401, detail="Device has no credential set.")

    if stored_hash.startswith("$2"):
        # Direct bcrypt (passlib dropped, §6 #15). Fail CLOSED on any error —
        # e.g. an over-72-byte key from an attacker, which bcrypt rejects with
        # ValueError; that must be a 401, never a 500 or a pass-through.
        try:
            ok = bcrypt.checkpw(x_api_key.encode("utf-8"), stored_hash.encode("utf-8"))
        except (ValueError, TypeError):
            ok = False
    else:
        ok = hmac.compare_digest(stored_hash, x_api_key)
    if not ok:
        logger.warning("API key mismatch for device %s — rejected", x_device_id)
        raise HTTPException(status_code=401, detail="Invalid API key.")

    return device


# ── Module-level singleton orchestrator (V3, unchanged) ──────────────────
# Keep one instance alive so models, baselines, and state persist across calls.

_orchestrator = None


def _get_orchestrator():
    """Return the singleton DetectionOrchestrator, creating it once."""
    global _orchestrator
    if _orchestrator is None:
        from lsadra.detection.detection_orchestrator import DetectionOrchestrator
        _orchestrator = DetectionOrchestrator()
    return _orchestrator


def run_online_detection(device_id: str) -> None:
    """Detection-worker entry point (worker thread, never a request handler)."""
    _get_orchestrator().run_for_new_events(device_id=device_id)


# ── Online detection hand-off ─────────────────────────────────────────────
# Handlers never run detection: they reserve a slot on the detection queue
# before writing and commit it after the write (lsadra/detection/
# detection_worker.py). A full queue is a 503 + Retry-After with nothing
# written, so the agent's retry cannot store the batch twice.


def _reserve_detection(device_id: str) -> bool:
    """Admit this batch for detection, or raise 503 before anything is stored.

    Returns False when detection is skipped (BENCH_SKIP_DETECTION, dev only).
    """
    if BENCH_SKIP_DETECTION:
        return False
    if not detection_queue.reserve(device_id):
        logger.warning("Detection queue full — batch from device %s refused (503)", device_id)
        raise HTTPException(
            status_code=503,
            detail="Detection queue is full; the batch was not stored. Retry later.",
            headers={"Retry-After": str(DETECTION_QUEUE_RETRY_AFTER_SECONDS)},
        )
    return True


async def _store_reserved(device_id: str, rows: List[Dict[str, Any]], detect: bool) -> int:
    """Write *rows* + touch the device off the event loop, then settle detection.

    The storage call runs in the threadpool (one connection, one transaction:
    :func:`store_batch_and_touch`). The detection reservation was taken on the
    loop *before* this call and is committed or released here, back on the
    loop — the queue is only ever touched from the event-loop thread.
    """
    try:
        count = await run_in_threadpool(store_batch_and_touch, device_id, rows)
    except BaseException:
        if detect:
            detection_queue.release(device_id)
        raise
    if detect:
        detection_queue.commit(device_id)
    return count


# ── V4: IngestionManager singleton ────────────────────────────────────────
# [V4 ENHANCEMENT — gap: multi-source ingestion]
# [DESIGN CHOICE] Singleton keeps parser chain and stats alive across requests.

_ingest_manager = None


def _get_ingest_manager():
    """Return the singleton IngestionManager, creating it once."""
    global _ingest_manager
    if _ingest_manager is None:
        from lsadra.ingestion.ingestion_manager import IngestionManager
        _ingest_manager = IngestionManager()
    return _ingest_manager


# ── Endpoint ──────────────────────────────────────────────────────────────


@router.post("/batch", summary="Ingest a batch of normalized events")
async def ingest_batch(
    batch: EventBatch,
    device: Dict[str, Any] = Depends(_authenticate_device),
) -> Dict[str, Any]:
    """
    Accept a batch of events from an endpoint agent.

    After inserting events, schedules online detection for this device on the
    detection worker (never inline).
    """
    device_id: str = device["id"]
    user_id: str = device["user_id"]

    _check_rate_limit(device_id)
    detect = _reserve_detection(device_id)

    # Build rows for bulk insert
    rows = []
    for ev in batch.events:
        rows.append(
            {
                "timestamp": ev.timestamp.isoformat(),
                "device_id": device_id,
                "user_id": user_id,
                "host": ev.host,
                "effective_username": ev.effective_username,
                "source_ip": ev.source_ip,
                "event_type": ev.event_type,
                "raw_message": ev.raw_message,
                "attributes": ev.attributes,
                "is_synthetic": False,
            }
        )

    # Write off the loop; on success schedule online detection (worker-side;
    # BENCH_SKIP_DETECTION is dev-mode-only and skips it — config.py refuses
    # it otherwise), on failure give the reservation back.
    count = await _store_reserved(device_id, rows, detect)
    logger.info("Ingested %d events from device %s", count, device_id)

    return {"status": "ok", "events_accepted": count}


# ── V4: Raw log ingestion endpoint ────────────────────────────────────────
# [V4 ENHANCEMENT — gap: multi-source ingestion]


class RawLogLine(BaseModel):
    """Schema for a single raw log line from any supported source."""

    model_config = ConfigDict(extra="forbid")

    raw_line: str = Field(..., max_length=MAX_RAW_MESSAGE_LENGTH)
    source_hint: Optional[SourceHint] = Field(
        default=None,
        description="Optional parser hint: ssh|syslog|windows|network|endpoint",
    )


class RawLogBatch(BaseModel):
    """Batch of raw log lines from one device."""

    model_config = ConfigDict(extra="forbid")

    lines: List[RawLogLine] = Field(..., max_length=MAX_EVENTS_PER_BATCH)


def _raw_event_host(event: Dict[str, Any]) -> str:
    """
    Hostname for a parsed /raw event, taken from the log line itself.

    Parsers report it as a top-level ``host`` (SSH), ``extra.host`` (syslog) or
    ``extra.computer`` (Windows). Unknown → "". Never the device ID: that is
    the authenticated identity and already lives in ``device_id``.
    """
    extra = event.get("extra") or {}
    host = event.get("host") or extra.get("host") or extra.get("computer") or ""
    return str(host)[:MAX_HOSTNAME_LENGTH]


@router.post("/raw", summary="[V4] Ingest raw log lines via IngestionManager")
async def ingest_raw_batch(
    batch: RawLogBatch,
    device: Dict[str, Any] = Depends(_authenticate_device),
) -> Dict[str, Any]:
    """
    Accept a batch of raw log lines from any supported source.

    Routes each line through the V4 IngestionManager for auto-detection
    and parsing, then stores the resulting unified events (off the event
    loop) and schedules online detection on the detection worker.

    [V4 ENHANCEMENT — gap: multi-source ingestion]
    [GLASSWING ALIGNMENT — central ingestion orchestrator]

    Args:
        batch:  Batch of raw log lines with optional source_hint.
        device: Authenticated device record (from device headers).

    Returns:
        status, accepted count, parse error count, per-source breakdown.
    """
    device_id: str = device["id"]
    user_id:   str = device["user_id"]

    _check_rate_limit(device_id)

    manager  = _get_ingest_manager()
    accepted = 0
    parse_errors = 0
    source_counts: Dict[str, int] = {}

    db_rows: List[Dict[str, Any]] = []

    for line_obj in batch.lines:
        try:
            event = manager.ingest_line(
                raw_line=line_obj.raw_line,
                device_id=device_id,
                hint=line_obj.source_hint,
            )
            if event is None:
                parse_errors += 1
                continue

            # Map V4 event schema to V3 DB row schema
            db_row = {
                "timestamp":          event.get("timestamp"),
                "device_id":          device_id,
                "user_id":            user_id,
                "host":               _raw_event_host(event),
                "effective_username": event.get("username") or "",
                "source_ip":          event.get("source_ip"),
                "event_type":         event.get("event_type"),
                "raw_message":        event.get("raw", "")[:MAX_RAW_MESSAGE_LENGTH],
                "attributes":         event.get("extra", {}),
                "is_synthetic":       False,
            }
            db_rows.append(db_row)
            accepted += 1

            src = event.get("source_type", "unknown")
            source_counts[src] = source_counts.get(src, 0) + 1
        except Exception:
            logger.exception("[V4] Failed to ingest raw line: %.120s", line_obj.raw_line)
            parse_errors += 1

    detect = _reserve_detection(device_id)
    if db_rows:
        await _store_reserved(device_id, db_rows, detect)
        logger.info(
            "[V4] Ingested %d events from device %s (errors: %d, sources: %s)",
            accepted, device_id, parse_errors, source_counts,
        )
    elif detect:
        # ── schedule online detection (V3 behaviour preserved: scheduled even
        # when no line parsed, so throttled-over events still get picked up) ──
        detection_queue.commit(device_id)

    return {
        "status":       "ok",
        "accepted":     accepted,
        "parse_errors": parse_errors,
        "source_breakdown": source_counts,
    }


@router.get("/stats", summary="[V4] Get ingestion statistics by source type")
async def get_ingest_stats(
    device: Dict[str, Any] = Depends(_authenticate_device),
) -> Dict[str, Any]:
    """
    Return per-source ingestion statistics from the IngestionManager.

    [V4 ENHANCEMENT — gap: ingestion health monitoring]

    Returns:
        Dict of source_type → {events, errors, last_event}.
    """
    manager = _get_ingest_manager()
    return {"status": "ok", "stats": manager.get_source_stats()}
