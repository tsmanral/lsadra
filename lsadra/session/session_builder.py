"""
LSADRA V2 — Session builder.

Groups contiguous events from the same (device_id, source_ip) into logical
sessions separated by a configurable inactivity gap.
"""

from datetime import timedelta
from typing import Any, Dict, List

import pandas as pd

from lsadra.features.timestamps import parse_event_timestamps


class SessionBuilder:
    """
    Cluster events into sessions based on an inactivity timeout.

    A session ends when there is a gap of more than ``timeout_minutes``
    between consecutive events from the same (device, IP) pair.
    """

    def __init__(self, timeout_minutes: int = 30):
        self.timeout = timedelta(minutes=timeout_minutes)

    def build(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Assign a ``session_id`` to each event.

        Args:
            events: List of event dicts (must contain *timestamp*,
                    *device_id*, *source_ip*).

        Returns:
            The same events list with an added ``session_id`` key.
        """
        if not events:
            return events

        df = pd.DataFrame(events)
        df["timestamp"] = parse_event_timestamps(df["timestamp"])
        df = df.sort_values("timestamp")

        session_col: List[int] = []
        session_counter = 0
        last_seen: Dict[str, pd.Timestamp] = {}

        for _, row in df.iterrows():
            key = f"{row.get('device_id', '')}|{row.get('source_ip', '')}"
            ts = row["timestamp"]

            if key in last_seen and (ts - last_seen[key]) <= self.timeout:
                session_col.append(session_counter)
            else:
                session_counter += 1
                session_col.append(session_counter)

            last_seen[key] = ts

        df["session_id"] = session_col

        return df.to_dict(orient="records")
