"""Unit tests for temporal and behavioral feature extraction."""

import numpy as np
import pandas as pd
import pytest

from lsadra.features.behavioral_features import extract_behavioral_features
from lsadra.features.temporal_features import extract_temporal_features


def _make_events(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


class TestExtractTemporalFeatures:
    """Tests for extract_temporal_features."""

    def test_normal_input_columns_and_values(self):
        # 2026-11-16 is a Monday (day_of_week=0), 2026-11-14 is a Saturday (day_of_week=5)
        df = _make_events(
            [
                {
                    "timestamp": "2026-11-16T14:30:00Z",
                    "source_ip": "192.0.2.10",
                },
                {
                    "timestamp": "2026-11-16T14:32:00Z",
                    "source_ip": "192.0.2.10",
                },
                {
                    "timestamp": "2026-11-14T23:15:00Z",
                    "source_ip": "198.51.100.20",
                },
            ]
        )

        out = extract_temporal_features(df)

        expected_cols = {
            "hour",
            "minute",
            "day_of_week",
            "hour_sin",
            "hour_cos",
            "is_off_hours",
            "is_weekend",
            "time_since_last_event_ip",
        }
        assert expected_cols.issubset(out.columns)
        assert len(out) == 3

        # Output is sorted by timestamp ascending: Saturday 23:15 first, then Monday 14:30, 14:32
        sat_row = out.iloc[0]
        assert sat_row["hour"] == 23
        assert sat_row["minute"] == 15
        assert sat_row["day_of_week"] == 5
        assert sat_row["is_weekend"] == 1
        assert sat_row["is_off_hours"] == 1
        assert sat_row["time_since_last_event_ip"] == 0.0

        mon_first = out.iloc[1]
        assert mon_first["hour"] == 14
        assert mon_first["minute"] == 30
        assert mon_first["day_of_week"] == 0
        assert mon_first["is_weekend"] == 0
        assert mon_first["is_off_hours"] == 0
        assert mon_first["time_since_last_event_ip"] == 0.0

        mon_second = out.iloc[2]
        assert mon_second["time_since_last_event_ip"] == pytest.approx(120.0)

    def test_midnight_and_weekend_boundaries(self):
        # 2026-11-15 is a Sunday (day_of_week=6) at 00:00:00
        df = _make_events(
            [
                {
                    "timestamp": "2026-11-15T00:00:00Z",
                    "source_ip": "203.0.113.5",
                }
            ]
        )

        out = extract_temporal_features(df)

        row = out.iloc[0]
        assert row["hour"] == 0
        assert row["minute"] == 0
        assert row["day_of_week"] == 6
        assert row["hour_sin"] == pytest.approx(0.0, abs=1e-9)
        assert row["hour_cos"] == pytest.approx(1.0, abs=1e-9)
        assert row["is_off_hours"] == 1
        assert row["is_weekend"] == 1
        assert row["time_since_last_event_ip"] == 0.0

    def test_single_event_without_source_ip(self):
        df = _make_events([{"timestamp": "2026-11-18T10:05:00Z"}])

        out = extract_temporal_features(df)

        assert len(out) == 1
        assert out.iloc[0]["hour"] == 10
        assert out.iloc[0]["is_off_hours"] == 0
        assert "time_since_last_event_ip" not in out.columns

    def test_empty_dataframe_with_expected_columns(self):
        df = pd.DataFrame(columns=["timestamp", "source_ip"])

        out = extract_temporal_features(df)

        assert out.empty
        assert list(out.columns) == ["timestamp", "source_ip"]


class TestExtractBehavioralFeatures:
    """Tests for extract_behavioral_features."""

    def test_normal_input_columns_and_rolling_metrics(self):
        df = _make_events(
            [
                {
                    "timestamp": "2026-11-16T10:00:00Z",
                    "source_ip": "192.0.2.10",
                    "effective_username": "alice.demo",
                    "event_type": "ssh_failed_password",
                },
                {
                    "timestamp": "2026-11-16T10:05:00Z",
                    "source_ip": "192.0.2.10",
                    "effective_username": "bob.demo",
                    "event_type": "ssh_failed_password",
                },
                {
                    "timestamp": "2026-11-16T10:10:00Z",
                    "source_ip": "192.0.2.10",
                    "effective_username": "alice.demo",
                    "event_type": "auth_success",
                },
                {
                    "timestamp": "2026-11-16T10:12:00Z",
                    "source_ip": "198.51.100.20",
                    "effective_username": "carol.demo",
                    "event_type": "auth_success",
                },
            ]
        )

        out = extract_behavioral_features(df)

        expected_cols = {
            "is_failure",
            "is_success",
            "username_id",
            "unique_users_15m",
            "failures_15m",
            "successes_15m",
            "failure_ratio_15m",
        }
        assert expected_cols.issubset(out.columns)
        assert len(out) == 4

        # Third row (10:10 on 192.0.2.10) sees 2 unique users (alice.demo, bob.demo),
        # 2 failures, and 1 success within the 15-minute window.
        third = out.iloc[2]
        assert third["unique_users_15m"] == pytest.approx(2.0)
        assert third["failures_15m"] == pytest.approx(2.0)
        assert third["successes_15m"] == pytest.approx(1.0)
        assert third["failure_ratio_15m"] == pytest.approx(2.0 / 3.0, rel=1e-6)

        # Fourth row (10:12 on 198.51.100.20) is isolated to its own IP.
        fourth = out.iloc[3]
        assert fourth["unique_users_15m"] == pytest.approx(1.0)
        assert fourth["failures_15m"] == pytest.approx(0.0)
        assert fourth["successes_15m"] == pytest.approx(1.0)
        assert fourth["failure_ratio_15m"] == pytest.approx(0.0, abs=1e-9)

    def test_single_event_at_midnight_boundary(self):
        df = _make_events(
            [
                {
                    "timestamp": "2026-11-15T00:00:00Z",
                    "source_ip": "203.0.113.5",
                    "effective_username": "dan.demo",
                    "event_type": "ssh_failed_password",
                }
            ]
        )

        out = extract_behavioral_features(df)

        assert len(out) == 1
        row = out.iloc[0]
        assert row["is_failure"] == 1
        assert row["is_success"] == 0
        assert row["unique_users_15m"] == pytest.approx(1.0)
        assert row["failures_15m"] == pytest.approx(1.0)
        assert row["successes_15m"] == pytest.approx(0.0)
        assert np.isclose(row["failure_ratio_15m"], 1.0, rtol=1e-6)

    def test_empty_dataframe_with_expected_columns(self):
        df = pd.DataFrame(columns=["timestamp", "source_ip", "effective_username", "event_type"])

        out = extract_behavioral_features(df)

        assert out.empty
        assert list(out.columns) == [
            "timestamp",
            "source_ip",
            "effective_username",
            "event_type",
        ]
