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
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "sentinel_v3.db"
LOG_DIR = PROJECT_ROOT / "logs"
MODEL_DIR = DATA_DIR / "models"

# ---------------------------------------------------------------------------
# Runtime mode
# ---------------------------------------------------------------------------
# Dev mode relaxes production boot guards (per-boot JWT secret, optional TLS)
# for LOCAL DEVELOPMENT ONLY. Never set true in production. (§6 #4/#6)
DEV_MODE: bool = os.getenv("LSADRA_DEV_MODE", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------
API_HOST: str = os.getenv("LSADRA_API_HOST", "0.0.0.0")
API_PORT: int = int(os.getenv("LSADRA_API_PORT", "8000"))
DASHBOARD_PORT: int = int(os.getenv("LSADRA_DASH_PORT", "8501"))

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
if _jwt_secret_env:
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
        "LSADRA_DEV_MODE=true for local development."
    )
TOKEN_ALGORITHM: str = "HS256"
JWT_EXPIRATION_MINUTES: int = int(os.getenv("LSADRA_JWT_EXPIRATION_MINUTES", "480"))
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
# Input Validation Caps
# ---------------------------------------------------------------------------
MAX_USERNAME_LENGTH: int = 128
MAX_HOSTNAME_LENGTH: int = 255
MAX_RAW_MESSAGE_LENGTH: int = 4096
MAX_EVENTS_PER_BATCH: int = 100

# ---------------------------------------------------------------------------
# Detection — Baselining
# ---------------------------------------------------------------------------
MIN_BASELINE_EVENTS: int = int(os.getenv("LSADRA_MIN_BASELINE_EVENTS", "5"))

# ---------------------------------------------------------------------------
# Detection — Thresholds
# ---------------------------------------------------------------------------
DETECTION_THROTTLE_SECONDS: float = 5.0  # min gap between online detection runs
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
# Feature Drift Detection
# ---------------------------------------------------------------------------
PSI_DRIFT_THRESHOLD: float = float(os.getenv("LSADRA_PSI_DRIFT_THRESHOLD", "0.2"))
FP_RATE_THRESHOLD: float = float(os.getenv("LSADRA_FP_RATE_THRESHOLD", "0.15"))

# ---------------------------------------------------------------------------
# Threat Intelligence
# ---------------------------------------------------------------------------
ABUSEIPDB_API_KEY: str = os.getenv("LSADRA_ABUSEIPDB_API_KEY", "")
THREAT_INTEL_CACHE_HOURS: int = int(os.getenv("LSADRA_TI_CACHE_HOURS", "24"))

# ---------------------------------------------------------------------------
# Metrics Aggregation
# ---------------------------------------------------------------------------
METRICS_AGGREGATION_INTERVAL_MINUTES: int = int(
    os.getenv("LSADRA_METRICS_INTERVAL_MINUTES", "5")
)

# ---------------------------------------------------------------------------
# Data Retention
# ---------------------------------------------------------------------------
RETENTION_DAYS: int = int(os.getenv("LSADRA_RETENTION_DAYS", "30"))
DATA_RETENTION_DAYS: int = RETENTION_DAYS  # alias

# ---------------------------------------------------------------------------
# V4 Configuration Keys
# [V4 ENHANCEMENT — gap: multi-source ingestion, dynamic severity, FP tuning]
# ---------------------------------------------------------------------------

# Ingestion parser chain: maximum bytes stored per raw log line
MAX_RAW_LINE_LENGTH: int = int(os.getenv("LSADRA_V4_MAX_RAW_LINE", "2048"))

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
