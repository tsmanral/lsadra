"""
LSADRA — Tolerant event timestamp parsing.

Agents and parsers do not all write timestamps the same way: some include
fractional seconds and some do not, some carry a UTC offset and some are naive,
and a hostile or broken sender can put anything in the field. Feature
extraction must never fail on that input, because a failure there stops
detection for the whole batch.

``parse_event_timestamps`` turns any mix of formats into one naive-UTC
``datetime64`` series with no missing values:

* Every ISO 8601 variant is parsed element by element (naive values are taken
  as UTC, offsets are converted to UTC).
* Anything else is tried with pandas' per-element format inference.
* A value that still cannot be parsed takes the timestamp of its nearest
  parsable neighbour in the batch, or the current UTC time when nothing in the
  batch parses, so the event is still scored instead of dropped.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pandas as pd

logger = logging.getLogger(__name__)


def _to_utc(values: pd.Series, **kwargs) -> pd.Series:
    try:
        return pd.to_datetime(values, utc=True, errors="coerce", **kwargs)
    except (ValueError, TypeError, OverflowError):
        return pd.Series(pd.NaT, index=values.index, dtype="datetime64[ns, UTC]")


def parse_event_timestamps(values: pd.Series) -> pd.Series:
    """Return *values* as naive-UTC datetimes with every missing value filled."""
    if values.empty:
        return pd.to_datetime(values)

    if pd.api.types.is_datetime64_any_dtype(values):
        parsed = values.dt.tz_convert("UTC") if values.dt.tz is not None else values.dt.tz_localize("UTC")
    else:
        as_text = values.where(values.isna(), values.astype(str))
        parsed = _to_utc(as_text, format="ISO8601")
        missing = parsed.isna() & as_text.notna()
        if missing.any():
            parsed.loc[missing] = _to_utc(as_text[missing], format="mixed")

    parsed = parsed.dt.tz_localize(None)

    bad = int(parsed.isna().sum())
    if bad:
        logger.warning("%d event timestamp(s) could not be parsed; using nearest valid time.", bad)
        parsed = parsed.ffill().bfill()
        if parsed.isna().any():
            now = pd.Timestamp(datetime.now(timezone.utc).replace(tzinfo=None))
            parsed = parsed.fillna(now)

    return parsed.astype("datetime64[ns]")
