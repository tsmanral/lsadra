"""
Central configuration for LSADRA V3.

All tuneable parameters, file paths, secrets, and resource limits are defined here.
Environment variables override defaults where noted.
"""

import logging
import os
import secrets
import warnings
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Loudly flag legacy SENTINEL_* env vars — they were renamed to LSADRA_* and are
# now IGNORED. Without this, an upgrade silently falls back to defaults: the JWT
# secret regenerates (sessions / cross-service auth break) and controls like TLS
# enforcement revert. Fail loud, not silent.
_legacy_env = sorted(k for k in os.environ if k.startswith("SENTINEL_"))
if _legacy_env:
    warnings.warn(
        "Ignoring legacy env vars (rename SENTINEL_* -> LSADRA_*): " + ", ".join(_legacy_env),
        stacklevel=2,
    )

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _dir_from_env(name: str, default: Path) -> Path:
    """An absolute folder from *name*, or *default* when unset or blank."""
    value = os.getenv(name, "").strip()
    return Path(value).expanduser().resolve() if value else default


# Where the database, models, TLS material and runtime intel live. Defaults to
# data/ in the checkout; an installed package or the desktop app points it at a
# per-user folder with LSADRA_DATA_DIR.
DATA_DIR = _dir_from_env("LSADRA_DATA_DIR", PROJECT_ROOT / "data")
DB_PATH = DATA_DIR / "sentinel_v3.db"
LOG_DIR = _dir_from_env("LSADRA_LOG_DIR", PROJECT_ROOT / "logs")
MODEL_DIR = DATA_DIR / "models"

# ---------------------------------------------------------------------------
# Runtime mode
# ---------------------------------------------------------------------------
# Dev mode relaxes production boot guards (per-boot JWT secret, optional TLS)
# for LOCAL DEVELOPMENT ONLY. Never set true in production. (§6 #4/#6)
DEV_MODE: bool = os.getenv("LSADRA_DEV_MODE", "false").lower() == "true"

# Benchmark-only switch (benchmarks/run_ingest_bench.py): skip online detection
# on the ingestion request path so DB cost and ML cost can be measured apart.
# Dev mode only — a production core that silently stops detecting is a security
# failure, so setting it outside dev mode refuses to boot rather than being
# ignored or honoured.
BENCH_SKIP_DETECTION: bool = (
    os.getenv("LSADRA_BENCH_SKIP_DETECTION", "false").lower() == "true"
)
if BENCH_SKIP_DETECTION and not DEV_MODE:
    raise RuntimeError(
        "LSADRA_BENCH_SKIP_DETECTION=true is a benchmark switch and requires "
        "LSADRA_DEV_MODE=true. Refusing to start a core with detection disabled."
    )

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------
# Loopback by default (G-8). Listening on another interface is an explicit
# opt-in, and the launcher (lsadra/serve.py) then refuses to serve plain HTTP
# unless TLS is configured, generated, or terminated by a trusted proxy.
API_HOST: str = os.getenv("LSADRA_API_HOST", "127.0.0.1")
API_PORT: int = int(os.getenv("LSADRA_API_PORT", "8000"))

# CORS: explicit browser-origin allowlist for the SPA (comma-separated).
# Empty (default) = no cross-origin access. Agents authenticate with header
# tokens, not browser credentials, so credentialed CORS is never enabled.
CORS_ALLOWED_ORIGINS: list = [
    o.strip() for o in os.getenv("LSADRA_CORS_ORIGINS", "").split(",") if o.strip()
]

# ---------------------------------------------------------------------------
# Security — TLS
# ---------------------------------------------------------------------------
# TLS required by default OUTSIDE dev mode — agents ship API keys over the wire,
# so plaintext HTTP must be an explicit dev-only opt-out. (§6 #6)
_require_tls_default = "false" if DEV_MODE else "true"
REQUIRE_TLS: bool = os.getenv("LSADRA_REQUIRE_TLS", _require_tls_default).lower() == "true"

# Reverse-proxy IPs whose X-Forwarded-Proto header may be trusted for TLS
# enforcement (comma-separated). Empty (default) = header is never trusted.
TRUSTED_PROXY_IPS: frozenset = frozenset(
    ip.strip() for ip in os.getenv("LSADRA_TRUSTED_PROXY_IPS", "").split(",") if ip.strip()
)
TLS_CERT_PATH: str = os.getenv("LSADRA_TLS_CERT", "")
TLS_KEY_PATH: str = os.getenv("LSADRA_TLS_KEY", "")

# ---------------------------------------------------------------------------
# Security — JWT / RBAC
# ---------------------------------------------------------------------------
# Secret used to sign JWTs. Outside dev mode a stable secret is MANDATORY — a
# per-boot random secret silently invalidates every issued token on restart, so
# the server refuses to start without LSADRA_JWT_SECRET. The old silent
# SECRET_KEY -> JWT_SECRET fallback is removed. (§6 #4)
_jwt_secret_env = os.getenv("LSADRA_JWT_SECRET")

# A JWT secret must be secret: anything copied from documentation, or short
# enough to guess, lets whoever reads the docs forge ADMIN tokens. Outside dev
# mode such a value is refused like a missing one. (Placeholders are compared
# case-insensitively; length is counted in bytes.)
JWT_SECRET_MIN_BYTES: int = 32
_KNOWN_PLACEHOLDER_SECRETS = frozenset({
    "changeme-in-production",
    "changeme",
    "change-me",
    "changeit",
    "secret",
    "your-secret-key",
    "your-jwt-secret",
    "replace-me",
})


def _jwt_secret_problem(value: str) -> Optional[str]:
    """Why *value* is unsafe as a JWT secret, or None when it is acceptable."""
    if value.strip().lower() in _KNOWN_PLACEHOLDER_SECRETS:
        return "it is a documented placeholder"
    if len(value.encode("utf-8")) < JWT_SECRET_MIN_BYTES:
        return f"it is shorter than {JWT_SECRET_MIN_BYTES} bytes"
    return None


_JWT_SECRET_HOWTO = (
    'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
)

if _jwt_secret_env:
    _problem = _jwt_secret_problem(_jwt_secret_env)
    if _problem and not DEV_MODE:
        raise RuntimeError(
            f"LSADRA_JWT_SECRET is not safe to use: {_problem}. Refusing to start "
            f"with a guessable token-signing key. {_JWT_SECRET_HOWTO}"
        )
    if _problem:
        logger.warning("LSADRA_DEV_MODE: LSADRA_JWT_SECRET is weak (%s).", _problem)
    JWT_SECRET: str = _jwt_secret_env
elif DEV_MODE:
    JWT_SECRET = secrets.token_urlsafe(32)
    logger.warning(
        "LSADRA_DEV_MODE: no LSADRA_JWT_SECRET set — using a random per-boot "
        "secret; all issued tokens invalidate on restart. Set LSADRA_JWT_SECRET "
        "for stable sessions."
    )
else:
    raise RuntimeError(
        "LSADRA_JWT_SECRET is required outside dev mode. Refusing to start with "
        "an insecure per-boot secret. Set LSADRA_JWT_SECRET, or set "
        f"LSADRA_DEV_MODE=true for local development. {_JWT_SECRET_HOWTO}"
    )
TOKEN_ALGORITHM: str = "HS256"

# Self-service sign-up on /api/auth/register. Off by default outside dev mode:
# otherwise anyone who can reach the port can create an account. Admins are
# created with `python -m lsadra.admin_cli create-admin`, and an admin can add
# users through POST /api/dashboard/users. Set true to open sign-up on purpose.
ALLOW_SIGNUP: bool = os.getenv(
    "LSADRA_ALLOW_SIGNUP", "true" if DEV_MODE else "false"
).lower() == "true"
# 60-minute sessions (G-9). Logout, a role or password change, or disabling the
# account also ends every earlier session at once (users.token_version).
JWT_EXPIRATION_MINUTES: int = int(os.getenv("LSADRA_JWT_EXPIRATION_MINUTES", "60"))
REGISTRATION_TOKEN_LIFETIME_MINUTES: int = 15  # single-use, short-lived

# ---------------------------------------------------------------------------
# Rate Limiting (per-window)
# ---------------------------------------------------------------------------
RATE_LIMIT_REGISTER_PER_MIN: int = 5   # POST /api/devices/register per IP
RATE_LIMIT_EVENTS_PER_MIN: int = 60    # POST /api/events/batch per device
# Max distinct rate-limit keys (devices / IPs) tracked before LRU eviction —
# bounds memory against dead or spoofed identifiers. (§6 #5)
RATE_LIMIT_MAX_KEYS: int = int(os.getenv("LSADRA_RATE_LIMIT_MAX_KEYS", "10000"))

# ---------------------------------------------------------------------------
# Device-auth credential cache (D7 Option A)
# ---------------------------------------------------------------------------
# A device key that passed bcrypt is remembered — as a keyed HMAC fingerprint,
# never the key — for at most this many seconds, bound to the stored hash it
# was verified against. The device row is still read on every request; only
# the repeat bcrypt verify is skipped. 0 disables the cache.
# (lsadra/ingestion/credential_cache.py)
DEVICE_AUTH_CACHE_TTL_SECONDS: float = float(os.getenv("LSADRA_DEVICE_AUTH_CACHE_TTL_SECONDS", "60"))
DEVICE_AUTH_CACHE_MAX_ENTRIES: int = int(os.getenv("LSADRA_DEVICE_AUTH_CACHE_MAX_ENTRIES", "10000"))
if not 0 <= DEVICE_AUTH_CACHE_TTL_SECONDS <= 3600:
    raise RuntimeError("LSADRA_DEVICE_AUTH_CACHE_TTL_SECONDS must be between 0 and 3600.")
if DEVICE_AUTH_CACHE_MAX_ENTRIES < 1:
    raise RuntimeError("LSADRA_DEVICE_AUTH_CACHE_MAX_ENTRIES must be >= 1.")

# ---------------------------------------------------------------------------
# Interpreter thread switch interval
# ---------------------------------------------------------------------------
# Online detection is CPU-bound Python on its own thread in the server process.
# With CPython's default 5 ms switch interval, request threads (auth, storage)
# that give up the GIL for every SQLite call queue behind it several times per
# request, which put a 100-400 ms tail on ingest while detection ran. A shorter
# interval hands the GIL back sooner; the server sets it at startup.
THREAD_SWITCH_INTERVAL_MS: float = float(os.getenv("LSADRA_THREAD_SWITCH_INTERVAL_MS", "0.5"))
if not 0 < THREAD_SWITCH_INTERVAL_MS <= 100:
    raise RuntimeError("LSADRA_THREAD_SWITCH_INTERVAL_MS must be > 0 and <= 100.")

# ---------------------------------------------------------------------------
# Sigma rule layer (lsadra/detection/sigma_engine.py). "shadow" (default) runs
# the rules and records matches without raising alerts; "alert" lets medium+
# matches raise alerts; "off" skips the layer. SIGMA_SUPPRESSIONS is an optional
# path to an operator-reviewed Sigma filter file, loaded with the bundled one.
SIGMA_MODE: str = os.getenv("LSADRA_SIGMA_MODE", "shadow").strip().lower()
if SIGMA_MODE not in ("off", "shadow", "alert"):
    raise RuntimeError("LSADRA_SIGMA_MODE must be off, shadow or alert.")
SIGMA_SUPPRESSIONS: str = os.getenv("LSADRA_SIGMA_SUPPRESSIONS", "").strip()

# ---------------------------------------------------------------------------
# Input Validation Caps
# These mirror docs/contracts/event-schema.v1.json (frozen). The schema file is
# the source of truth; tests/test_contracts.py fails if the two drift.
# /api/events/raw lines share MAX_RAW_MESSAGE_LENGTH.
# ---------------------------------------------------------------------------
MAX_USERNAME_LENGTH: int = 128
MAX_HOSTNAME_LENGTH: int = 255
MAX_RAW_MESSAGE_LENGTH: int = 4096
MAX_EVENTS_PER_BATCH: int = 100
MAX_EVENT_TYPE_LENGTH: int = 64
MAX_SOURCE_IP_LENGTH: int = 45
MAX_ATTRIBUTE_KEYS: int = 32
MAX_ATTRIBUTE_VALUE_LENGTH: int = 1024
MAX_ATTRIBUTES_BYTES: int = 8192

# ---------------------------------------------------------------------------
# Detection — Baselining
# ---------------------------------------------------------------------------
MIN_BASELINE_EVENTS: int = int(os.getenv("LSADRA_MIN_BASELINE_EVENTS", "5"))

# ---------------------------------------------------------------------------
# Detection — Thresholds
# ---------------------------------------------------------------------------
DETECTION_THROTTLE_SECONDS: float = 5.0  # min gap between online detection runs

# Online detection runs off the ingestion request path: handlers enqueue the
# device id and one worker drains it (lsadra/detection/detection_worker.py).
# The size bounds *distinct devices* waiting for a run (batches for a waiting
# device coalesce). When it is full, ingestion answers 503 + Retry-After before
# writing anything, so the agent's retry cannot duplicate events.
DETECTION_QUEUE_SIZE: int = int(os.getenv("LSADRA_DETECTION_QUEUE_SIZE", "256"))
if DETECTION_QUEUE_SIZE < 1:
    raise RuntimeError("LSADRA_DETECTION_QUEUE_SIZE must be >= 1.")
DETECTION_QUEUE_RETRY_AFTER_SECONDS: int = 5

# /ws/alerts: alerts buffered per connected client before the server gives up
# on a client that is not reading. It is closed with 1013 and should reconnect
# and backfill from GET /api/dashboard/anomalies (lsadra/api/alert_stream.py).
WS_ALERT_QUEUE_SIZE: int = int(os.getenv("LSADRA_WS_ALERT_QUEUE_SIZE", "256"))
if WS_ALERT_QUEUE_SIZE < 1:
    raise RuntimeError("LSADRA_WS_ALERT_QUEUE_SIZE must be >= 1.")
STATISTICAL_BASELINE_SIGMA: float = 3.0  # z-score threshold for Layer 1
AUTOENCODER_PERCENTILE_THRESHOLD: float = 95.0  # reconstruction-error percentile

# ---------------------------------------------------------------------------
# Severity Scoring
# ---------------------------------------------------------------------------
SEVERITY_THRESHOLDS: dict = {
    "CRITICAL": float(os.getenv("LSADRA_SEVERITY_CRITICAL", "0.9")),
    "HIGH": float(os.getenv("LSADRA_SEVERITY_HIGH", "0.7")),
    "MEDIUM": float(os.getenv("LSADRA_SEVERITY_MEDIUM", "0.4")),
    "LOW": float(os.getenv("LSADRA_SEVERITY_LOW", "0.0")),
}

# ---------------------------------------------------------------------------
# Incident Management
# ---------------------------------------------------------------------------
INCIDENT_WINDOW_MINUTES: int = int(os.getenv("LSADRA_INCIDENT_WINDOW_MINUTES", "15"))

# ---------------------------------------------------------------------------
# Device Monitoring
# ---------------------------------------------------------------------------
DEVICE_ONLINE_THRESHOLD_MINUTES: int = int(
    os.getenv("LSADRA_DEVICE_ONLINE_THRESHOLD_MINUTES", "5")
)

# ---------------------------------------------------------------------------
# Model Defaults
# ---------------------------------------------------------------------------
ENSEMBLE_CONTAMINATION: float = 0.05
AUTOENCODER_LATENT_DIM: int = 4
AUTOENCODER_EPOCHS: int = 50
AUTOENCODER_LR: float = 1e-3

# ---------------------------------------------------------------------------
# Model integrity and training controls (G-17, G-18)
# ---------------------------------------------------------------------------
# Every model file is listed in a manifest whose HMAC is keyed by a secret
# that lives outside the models folder, and is verified before it is
# deserialized. Defaults to a key derived from LSADRA_JWT_SECRET, so rotating
# that secret makes the current models unverifiable and they are retrained.
MODEL_SIGNING_KEY: str = os.getenv("LSADRA_MODEL_SIGNING_KEY", "")

# Training needs this many usable events across all devices (after events
# tied to anomalies or open incidents are dropped).
MIN_TRAINING_EVENTS: int = int(os.getenv("LSADRA_MIN_TRAINING_EVENTS", "50"))
# Most recent events considered for one training run.
TRAINING_MAX_EVENTS: int = int(os.getenv("LSADRA_TRAINING_MAX_EVENTS", "10000"))
# With more than one device, no device may supply more than this share of the
# training set, so one noisy or compromised host cannot define "normal".
TRAINING_MAX_DEVICE_SHARE: float = float(os.getenv("LSADRA_TRAINING_MAX_DEVICE_SHARE", "0.5"))
# Minimum gap between two training runs (manual or automatic).
RETRAIN_COOLDOWN_SECONDS: float = float(os.getenv("LSADRA_RETRAIN_COOLDOWN_SECONDS", "600"))
# A candidate model is promoted only if its ML layers still flag at least this
# share of the attack events in each canary scenario of the demo corpus.
CANARY_MIN_RECALL: float = float(os.getenv("LSADRA_CANARY_MIN_RECALL", "0.5"))
# While the live models were trained on fewer than TRAINING_MAX_EVENTS events,
# retrain automatically each time the stored event count has grown by this
# factor since the last training run (50 -> 100 -> 200 ...). The first model
# otherwise stays fitted on the first MIN_TRAINING_EVENTS events for good.
# Same gate, cooldown, canary and audit trail as every other run; 0 turns it off.
AUTO_RETRAIN_GROWTH: float = float(os.getenv("LSADRA_AUTO_RETRAIN_GROWTH", "2.0"))
# Phase 1 shadow scorer (ADR 0007): share of training events the ECOD shadow
# verdict may flag. Shadow verdicts are logged and returned, never alerted on.
SHADOW_ECOD_TARGET_FPR: float = float(os.getenv("LSADRA_SHADOW_ECOD_TARGET_FPR", "0.001"))
CANARY_SCENARIOS: List[str] = [
    s.strip()
    for s in os.getenv("LSADRA_CANARY_SCENARIOS", "ssh_bruteforce,injection_attempts").split(",")
    if s.strip()
]
# Drift is measured over this many hours of recent events.
DRIFT_WINDOW_HOURS: int = int(os.getenv("LSADRA_DRIFT_WINDOW_HOURS", "24"))

# ---------------------------------------------------------------------------
# Feature Drift Detection
# ---------------------------------------------------------------------------
PSI_DRIFT_THRESHOLD: float = float(os.getenv("LSADRA_PSI_DRIFT_THRESHOLD", "0.2"))
FP_RATE_THRESHOLD: float = float(os.getenv("LSADRA_FP_RATE_THRESHOLD", "0.15"))

# ---------------------------------------------------------------------------
# Threat Intelligence
# ---------------------------------------------------------------------------
# Two tiers (ADR 0004). The bundled tier ships inside the package as a signed,
# hash-verified SQLite file (CISA KEV, MITRE ATT&CK) and needs no key and no
# network. The runtime tier lives only in a local, gitignored intel_runtime.db,
# filled from sources the operator turns on; nothing in it is redistributed.
#
# Directory holding a newer signed bundle (intel-YYYYMMDD.sqlite + manifest.json
# + manifest.sig). Optional; the packaged bundle is the fallback. A bundle here
# is used only if its signature and hash verify against a trusted key.
INTEL_BUNDLE_DIR: str = os.getenv("LSADRA_INTEL_BUNDLE_DIR", "")
INTEL_RUNTIME_DB: Path = Path(
    os.getenv("LSADRA_INTEL_RUNTIME_DB", str(DATA_DIR / "intel_runtime.db"))
)
# Keyless runtime feeds to download (comma-separated): feodo, spamhaus_drop,
# tor_exits. Empty by default so a fresh install makes no outbound requests.
INTEL_FEEDS: list = [
    f.strip() for f in os.getenv("LSADRA_INTEL_FEEDS", "").split(",") if f.strip()
]
INTEL_FEED_REFRESH_HOURS: int = int(os.getenv("LSADRA_INTEL_FEED_REFRESH_HOURS", "12"))
# Optional keyed source. Lookups send the IP to AbuseIPDB, so they only happen
# when the operator sets a key.
ABUSEIPDB_API_KEY: str = os.getenv("LSADRA_ABUSEIPDB_API_KEY", "")
THREAT_INTEL_CACHE_HOURS: int = int(os.getenv("LSADRA_TI_CACHE_HOURS", "24"))
# Local IP geolocation: a MaxMind-format .mmdb file read on this machine (no
# lookup ever leaves it). Default search: data/geo/GeoLite2-City.mmdb, then
# GeoLite2-Country, then the DB-IP Lite equivalents. `python -m lsadra.intel
# geo-update` downloads GeoLite2 when a MaxMind account ID and license key are
# set, otherwise the keyless DB-IP Lite database (CC BY 4.0).
GEOIP_DB: str = os.getenv("LSADRA_GEOIP_DB", "")
GEO_DIR: Path = DATA_DIR / "geo"
MAXMIND_ACCOUNT_ID: str = os.getenv("LSADRA_MAXMIND_ACCOUNT_ID", "")
MAXMIND_LICENSE_KEY: str = os.getenv("LSADRA_MAXMIND_LICENSE_KEY", "")

# ---------------------------------------------------------------------------
# Metrics Aggregation
# ---------------------------------------------------------------------------
METRICS_AGGREGATION_INTERVAL_MINUTES: int = int(
    os.getenv("LSADRA_METRICS_INTERVAL_MINUTES", "5")
)

# ---------------------------------------------------------------------------
# Data Retention
# ---------------------------------------------------------------------------
# Tiered retention (gap G-35). Raw telemetry (normalized events, heartbeats)
# is the bulk of the database and the most personal, so it goes first. Alerts
# (anomalies) and the rollups built from them (5-minute metrics, drift records)
# are small and are what an investigation of a slow, months-old intrusion needs,
# so they stay a year. The alert tier never expires sooner than the raw tier.
RETENTION_DAYS: int = int(os.getenv("LSADRA_RETENTION_DAYS", "30"))
DATA_RETENTION_DAYS: int = RETENTION_DAYS  # alias
ALERT_RETENTION_DAYS: int = max(
    int(os.getenv("LSADRA_ALERT_RETENTION_DAYS", "365")), RETENTION_DAYS
)
# Bounded cleanup: each DELETE transaction removes at most this many rows, then
# commits and pauses so ingest writers waiting on the lock get it between
# batches instead of waiting out one long transaction. 1,000 rows held the lock
# ~40 ms per batch locally (5,000 rows: ~215 ms, near the 250 ms request gate).
RETENTION_BATCH_SIZE: int = int(os.getenv("LSADRA_RETENTION_BATCH_SIZE", "1000"))
RETENTION_BATCH_PAUSE_S: float = float(os.getenv("LSADRA_RETENTION_BATCH_PAUSE_S", "0.05"))
RETENTION_INTERVAL_MINUTES: int = int(os.getenv("LSADRA_RETENTION_INTERVAL_MINUTES", "60"))

# ---------------------------------------------------------------------------
# Background scheduler
# ---------------------------------------------------------------------------
# Started by server.py's lifespan. The test suite turns it off (tests/conftest.py)
# so a TestClient lifespan never runs jobs against a test database.
SCHEDULER_ENABLED: bool = os.getenv("LSADRA_SCHEDULER_ENABLED", "true").lower() == "true"
# Fills the ip_geolocation table from the local .mmdb file (see GEOIP_DB). It
# makes no network requests; it stays opt-in because it needs that file.
GEO_RESOLUTION_ENABLED: bool = os.getenv("LSADRA_GEO_RESOLUTION_ENABLED", "false").lower() == "true"

# ---------------------------------------------------------------------------
# V4 Configuration Keys
# [V4 ENHANCEMENT — gap: multi-source ingestion, dynamic severity, FP tuning]
# ---------------------------------------------------------------------------

# Ingestion health monitoring: minutes of silence before a source is flagged
INGESTION_SILENCE_THRESHOLD_MINUTES: int = int(
    os.getenv("LSADRA_V4_SILENCE_THRESHOLD_MINUTES", "30")
)

# Lateral movement detection: look-back window
LATERAL_MOVEMENT_WINDOW_MINUTES: int = int(
    os.getenv("LSADRA_V4_LAT_MOV_WINDOW_MINUTES", "30")
)

# Cross-source correlation: number of source types before elevation
CROSS_SOURCE_ELEVATION_THRESHOLD: int = int(
    os.getenv("LSADRA_V4_CROSS_SOURCE_ELEVATION", "2")
)

# V4 dynamic severity score thresholds (override SEVERITY_THRESHOLDS for V4 rules)
V4_SEVERITY_THRESHOLDS: dict = {
    "CRITICAL": float(os.getenv("LSADRA_V4_SEV_CRITICAL", "0.75")),
    "HIGH":     float(os.getenv("LSADRA_V4_SEV_HIGH",     "0.50")),
    "MEDIUM":   float(os.getenv("LSADRA_V4_SEV_MEDIUM",   "0.25")),
}

# Brute force rule thresholds (tunable by analyst feedback)
BRUTE_FORCE_5MIN_CRITICAL: int = int(os.getenv("LSADRA_V4_BF_5MIN_CRITICAL", "15"))
BRUTE_FORCE_5MIN_HIGH:     int = int(os.getenv("LSADRA_V4_BF_5MIN_HIGH",     "5"))
BRUTE_FORCE_15MIN_MEDIUM:  int = int(os.getenv("LSADRA_V4_BF_15MIN_MED",     "8"))

# Port scan thresholds
PORT_SCAN_CRITICAL_THRESHOLD: int = int(os.getenv("LSADRA_V4_PORT_SCAN_CRITICAL", "50"))
PORT_SCAN_HIGH_THRESHOLD:     int = int(os.getenv("LSADRA_V4_PORT_SCAN_HIGH",     "15"))

# Large data transfer threshold (bytes)
LARGE_TRANSFER_BYTES: int = int(os.getenv("LSADRA_V4_LARGE_TRANSFER_BYTES", "10000000"))

# Analyst feedback: maximum FP patterns to load for threshold tuning
MAX_FP_PATTERNS_FOR_TUNING: int = int(os.getenv("LSADRA_V4_MAX_FP_PATTERNS", "100"))


# ---------------------------------------------------------------------------
# Identity hardening (G-9, G-10, G-33)
# ---------------------------------------------------------------------------
# Password policy: minimum length plus a bundled offline list of common
# passwords (lsadra/security/common_passwords.txt). bcrypt reads 72 bytes at
# most, so longer passwords are refused rather than silently truncated.
MIN_PASSWORD_LENGTH: int = max(8, int(os.getenv("LSADRA_MIN_PASSWORD_LENGTH", "12")))

# Login throttling, checked before bcrypt runs. Failures are counted per
# username and per client IP over a sliding window; at the limit, the login
# route answers 429 with Retry-After until the oldest failure ages out.
LOGIN_FAILURE_WINDOW_SECONDS: int = int(os.getenv("LSADRA_LOGIN_FAILURE_WINDOW_SECONDS", "900"))
LOGIN_MAX_FAILURES_PER_USER: int = int(os.getenv("LSADRA_LOGIN_MAX_FAILURES_PER_USER", "5"))
LOGIN_MAX_FAILURES_PER_IP: int = int(os.getenv("LSADRA_LOGIN_MAX_FAILURES_PER_IP", "20"))

# TOTP second factor. "optional" (default): any account may enrol, and an
# enrolled account always needs a code. "required": ADMIN accounts cannot log
# in until they enrol (python -m lsadra.security.totp_cli enroll <user>).
ADMIN_TOTP: str = os.getenv("LSADRA_ADMIN_TOTP", "optional").strip().lower()
if ADMIN_TOTP not in ("optional", "required"):
    raise RuntimeError("LSADRA_ADMIN_TOTP must be 'optional' or 'required'.")

# Device key rotation: how long the previous key keeps working after a rotation,
# so an agent can pick up its new key without dropping events.
DEVICE_KEY_ROTATION_OVERLAP_MINUTES: int = int(
    os.getenv("LSADRA_DEVICE_KEY_ROTATION_OVERLAP_MINUTES", "10")
)

# ---------------------------------------------------------------------------
# Listener and TLS (G-8)
# ---------------------------------------------------------------------------
# Where a generated self-signed certificate is kept (first boot on a
# non-loopback address without LSADRA_TLS_CERT / LSADRA_TLS_KEY).
TLS_DIR: Path = DATA_DIR / "tls"
# Escape hatch for a container whose port is published on loopback only, or a
# lab network: serve plain HTTP on a non-loopback address. Logged loudly.
ALLOW_PLAINTEXT_LISTENER: bool = (
    os.getenv("LSADRA_ALLOW_PLAINTEXT_LISTENER", "false").lower() == "true"
)

# ---------------------------------------------------------------------------
# API surface and browser hardening (G-11)
# ---------------------------------------------------------------------------
# OpenAPI docs (/docs, /redoc, /openapi.json) are served in dev mode only.
EXPOSE_API_DOCS: bool = (
    os.getenv("LSADRA_EXPOSE_API_DOCS", "true" if DEV_MODE else "false").lower() == "true"
)
# Strict-Transport-Security max-age, sent only on HTTPS responses.
HSTS_MAX_AGE_SECONDS: int = int(os.getenv("LSADRA_HSTS_MAX_AGE_SECONDS", "31536000"))

# ---------------------------------------------------------------------------
# Audit trail and data at rest (G-26, G-27)
# ---------------------------------------------------------------------------
# audit_events rows are kept at least 365 days; the table's own trigger refuses
# an earlier delete, so a lower value is raised to 365.
AUDIT_RETENTION_DAYS: int = max(365, int(os.getenv("LSADRA_AUDIT_RETENTION_DAYS", "365")))
# Restrict the data directory to the server's own account at start-up
# (0700 directories, 0600 files; POSIX only).
RESTRICT_DATA_PERMISSIONS: bool = (
    os.getenv("LSADRA_RESTRICT_DATA_PERMISSIONS", "true").lower() == "true"
)
