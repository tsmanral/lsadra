"""
LSADRA — render-side sanitizer for log-derived strings (R8 injection shield).

Boundary rule
-------------
Log-derived strings never enter instruction positions. Every value that
originates from an ingested event (IP, user name, host/device, event type,
source type, rule reasons that embed those, timestamps, threat-intel fields)
is untrusted data. It reaches narrative text only through :func:`clean_field`,
and only in a *data* position of a fixed template. A future LLM receives
log-derived text only inside a data envelope and has no tool access; that
envelope and output-schema validation land with the LLM at M4. This module is
the M1 layer: it makes narrative text safe to store and to render as markdown
before any LLM exists.

What :func:`clean_field` does, in order
---------------------------------------
1. Coerces the value to ``str`` (``None`` becomes ``""``).
2. NFKC-normalizes, so fullwidth / compatibility look-alikes of markup
   characters (``＊`` ``｀`` ``＜``) fold to their ASCII forms *before* escaping.
3. Strips invisible and control characters: C0/C1 controls (``Cc``), format
   characters (``Cf`` — zero-width, bidi embeddings/overrides/isolates, BOM,
   Unicode tag characters), surrogates (``Cs``) and non-characters. Whitespace
   controls (tab, CR, LF, NEL) and line/paragraph separators become a single
   space so a value can never start a new markdown line.
4. Escapes markdown-significant characters with a backslash (the backslash
   itself first, so an attacker cannot pre-escape our escape).
5. Truncates to ``max_len`` output characters without splitting an escape
   sequence, and appends :data:`TRUNCATION_MARKER` when anything was cut.

Known limits (documented, not silently claimed): NFKC does not fold
cross-script confusables (e.g. Cyrillic ``а`` vs Latin ``a``) — the text stays
visibly present but may read as a look-alike; bare ``www.``/``http://`` text may
still be auto-linked by GFM renderers (escaping ``[``/``]``/``<``/``>`` blocks
every explicit link and autolink form).
"""

from __future__ import annotations

import unicodedata
from typing import Any

# Characters with markdown meaning in CommonMark / GFM / Streamlit markdown.
# Backslash MUST be escaped first (handled by per-character escaping below).
MARKDOWN_SPECIALS = frozenset("\\`*_[]<>~|$")

TRUNCATION_MARKER = "…(truncated)"

# Per-field output budgets (characters after escaping, before the marker).
MAX_IP = 64          # IPv6 text form is at most 45 chars; slack for "Unknown IP"
MAX_IDENT = 64       # user names, device ids, hosts
MAX_LABEL = 64       # event types, source types, attack types, MITRE ids
MAX_TIMESTAMP = 32   # ISO 8601 prefixes
MAX_TEXT = 256       # free text: rule reasons, urgency, recommendations

_WHITESPACE_CONTROLS = {"\t", "\n", "\r", "\x0b", "\x0c", "\x85", " ", " "}
_STRIP_CATEGORIES = {"Cc", "Cf", "Cs", "Cn"}


def _is_stripped(ch: str) -> bool:
    return unicodedata.category(ch) in _STRIP_CATEGORIES


def _strip_invisible(text: str) -> str:
    out = []
    for ch in text:
        if ch in _WHITESPACE_CONTROLS:
            out.append(" ")
        elif _is_stripped(ch):
            continue
        else:
            out.append(ch)
    return "".join(out)


def clean_field(value: Any, max_len: int = MAX_TEXT) -> str:
    """
    Return *value* as a string that is inert inside a markdown template.

    Guarantees for any input: the result contains no ``Cc``/``Cf``/``Cs``/``Cn``
    character, every markdown-special character is backslash-escaped, and
    ``len(result) <= max_len + len(TRUNCATION_MARKER)``.

    Args:
        value:   Any value; log-derived strings are the intended input.
        max_len: Output budget in characters, counted after escaping.

    Returns:
        The sanitized string (possibly ending in :data:`TRUNCATION_MARKER`).
    """
    if max_len < 1:
        raise ValueError("max_len must be >= 1")
    text = "" if value is None else str(value)
    text = unicodedata.normalize("NFKC", text)
    # NFKC can compose new code points; strip after normalizing, and once more
    # after re-normalizing so stripping cannot expose a new composable pair.
    text = unicodedata.normalize("NFKC", _strip_invisible(text))
    text = _strip_invisible(text)

    pieces = []
    used = 0
    truncated = False
    for ch in text:
        piece = "\\" + ch if ch in MARKDOWN_SPECIALS else ch
        if used + len(piece) > max_len:
            truncated = True
            break
        pieces.append(piece)
        used += len(piece)

    result = "".join(pieces)
    if truncated:
        result += TRUNCATION_MARKER
    return result


def clean_list(values: Any, max_items: int, max_len: int = MAX_IDENT) -> str:
    """Clean each item of an iterable (or a comma-separated string) and join with ", "."""
    if values is None:
        return ""
    if isinstance(values, str):
        items = values.split(",")
    else:
        items = list(values)
    cleaned = [clean_field(v.strip() if isinstance(v, str) else v, max_len) for v in items[:max_items]]
    return ", ".join(c for c in cleaned if c)
