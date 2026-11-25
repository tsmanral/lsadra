"""Password policy (G-10, ASVS 5.0 V6.2).

* At least ``MIN_PASSWORD_LENGTH`` characters (12 by default).
* At most 72 bytes in UTF-8: bcrypt ignores everything past that, so a longer
  password would silently be cut. It is refused instead.
* Not on the bundled offline list of common passwords, and not the username.

No composition rules (upper case, digits, symbols), as ASVS and NIST SP 800-63B
advise against them.
"""

from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, Optional

from lsadra import config

BCRYPT_MAX_BYTES = 72
_COMMON_PASSWORDS_FILE = Path(__file__).with_name("common_passwords.txt")


class PasswordPolicyError(ValueError):
    """The password does not meet the policy; the message is safe to show."""


@lru_cache(maxsize=1)
def _common_passwords() -> FrozenSet[str]:
    with _COMMON_PASSWORDS_FILE.open(encoding="utf-8") as fh:
        return frozenset(
            line.strip().lower() for line in fh if line.strip() and not line.startswith("#")
        )


def is_common_password(password: str) -> bool:
    return password.strip().lower() in _common_passwords()


def check_password_policy(password: str, username: Optional[str] = None) -> None:
    """Raise PasswordPolicyError if *password* is not acceptable."""
    minimum = config.MIN_PASSWORD_LENGTH
    if len(password) < minimum:
        raise PasswordPolicyError(f"Password must be at least {minimum} characters.")
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise PasswordPolicyError(f"Password must be at most {BCRYPT_MAX_BYTES} bytes.")
    if len(set(password)) == 1:
        raise PasswordPolicyError("Password must not repeat a single character.")
    if username and password.strip().lower() == username.strip().lower():
        raise PasswordPolicyError("Password must not be the username.")
    if is_common_password(password):
        raise PasswordPolicyError("Password is too common; choose another.")
