"""Make untrusted values safe to put in a log line.

Device-supplied strings (hostnames, parsed source types, raw log lines) end up
in the server log. A value carrying CR/LF or other control characters could
forge extra log entries or hide real ones from whoever reads the log, so every
such value goes through :func:`log_safe` first.
"""

from __future__ import annotations

from typing import Any

# Control characters other than CR/LF, rendered as visible escapes.
_CONTROL = {c: f"\\x{c:02x}" for c in (*range(0x00, 0x20), 0x7F) if c not in (0x0A, 0x0D)}

DEFAULT_MAX_LEN = 200


def log_safe(value: Any, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Return ``value`` as one printable line, at most ``max_len`` characters.

    Line breaks become the literal text ``\\r`` / ``\\n`` and other control
    characters become ``\\xNN``, so the result can never start a new log entry.
    Long values are cut and marked with ``...``.
    """
    text = str(value).translate(_CONTROL)
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text
