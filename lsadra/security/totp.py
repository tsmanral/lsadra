"""Time-based one-time passwords, RFC 6238 (G-33, ASVS 5.0 V6.3.3).

Standard parameters every authenticator app accepts: HMAC-SHA1, 30-second
steps, 6 digits. Verification accepts the previous, current and next step for
clock drift, and refuses a step at or before the last one used, so a code
cannot be replayed. Standard library only.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse
from typing import Optional

STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1


def generate_secret() -> str:
    """A new random 160-bit secret, base32 without padding."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** DIGITS)).zfill(DIGITS)


def current_step(now: Optional[float] = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def verify(secret: str, code: str, last_step: int = 0, now: Optional[float] = None) -> Optional[int]:
    """The matched step if *code* is valid and newer than *last_step*, else None."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    step = current_step(now)
    for candidate in range(step - DRIFT_STEPS, step + DRIFT_STEPS + 1):
        if candidate <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret: str, username: str, issuer: str = "LSADRA") -> str:
    label = urllib.parse.quote(f"{issuer}:{username}")
    query = urllib.parse.urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": STEP_SECONDS}
    )
    return f"otpauth://totp/{label}?{query}"
