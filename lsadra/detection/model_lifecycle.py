"""
Model lifecycle controls (G-18, G-19).

Training data hygiene, single-flight training, the canary gate before a
candidate model replaces the live one, rollback to the previous model, drift
reference quantiles and per-model cards. Model-agnostic: the same gates apply
when the ensemble is replaced by the ONNX stack of ADR 0007.

Flow of one training run (``DetectionOrchestrator.retrain``):

1. :func:`training_gate` admits one run at a time and enforces a cooldown.
2. :func:`select_training_events` takes recent events, drops those an anomaly
   points at or that fall inside an open incident's window, and caps any one
   device's share so a single host cannot define "normal" for every host.
3. The orchestrator fits a *candidate*; the live models keep serving.
4. :func:`run_canary` replays the attack scenarios of the demo corpus through
   the candidate's ML layers. A candidate that no longer flags them (the
   typical effect of poisoned training data) is rejected.
5. On promotion the current files are snapshotted to ``previous/`` first, so
   :meth:`DetectionOrchestrator.rollback` can restore them.

Every attempt, refused or not, leaves a row in ``model_training_runs``.
"""

from __future__ import annotations

import json
import logging
import math
import platform
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import numpy as np
import pandas as pd

from lsadra import config
from lsadra.features.feature_extractor import FEATURE_COLS
from lsadra.features.model_features import MODEL_FEATURE_NAMES
from lsadra.models.integrity import ModelIntegrityError, ModelStore

logger = logging.getLogger(__name__)

ENSEMBLE_FILE = "ensemble.joblib"
AUTOENCODER_FILE = "autoencoder.pt"
BASELINE_FILE = "baseline.json"
ECOD_FILE = "ecod.json"
REFERENCE_FILE = "reference.json"
PREVIOUS_DIR = "previous"
MODEL_NAMES = ("ensemble", "autoencoder", "baseline", "ecod")


def card_file(model_name: str) -> str:
    return f"{model_name}.card.json"


def model_dir() -> Path:
    """Current models folder (read at call time so tests can redirect it)."""
    return Path(config.MODEL_DIR)


def current_store(directory: Optional[Path] = None) -> ModelStore:
    return ModelStore(directory or model_dir())


def previous_store(directory: Optional[Path] = None) -> ModelStore:
    return ModelStore((directory or model_dir()) / PREVIOUS_DIR)


# ── generation counter (in-process model swaps) ──────────────────────────

_generation = 0
_generation_lock = threading.Lock()


def generation() -> int:
    return _generation


def bump_generation() -> int:
    global _generation
    with _generation_lock:
        _generation += 1
        return _generation


# ── single-flight gate ────────────────────────────────────────────────────


class TrainingRefused(Exception):
    """A training or rollback request was not started."""

    def __init__(self, reason: str, status_code: int, retry_after: Optional[int] = None):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code
        self.retry_after = retry_after


_train_lock = threading.Lock()
_next_allowed: Optional[float] = None  # time.monotonic() before which no run starts

# A run that found too few usable events retries sooner than the full cooldown.
SKIPPED_RUN_COOLDOWN_SECONDS = 30.0


class _GateTicket:
    """Handed to the body of :func:`training_gate`; it may shorten the next cooldown."""

    def __init__(self) -> None:
        self.cooldown: Optional[float] = None


def reset_training_gate() -> None:
    """Forget the cooldown (tests)."""
    global _next_allowed
    _next_allowed = None


def cooldown_remaining() -> float:
    if _next_allowed is None:
        return 0.0
    return max(0.0, _next_allowed - time.monotonic())


def is_training() -> bool:
    return _train_lock.locked()


@contextmanager
def training_gate(enforce_cooldown: bool = True) -> Iterator[_GateTicket]:
    """Admit one training/rollback at a time; optionally enforce the cooldown."""
    global _next_allowed
    if not _train_lock.acquire(blocking=False):
        raise TrainingRefused("A training run is already in progress.", 409)
    try:
        remaining = cooldown_remaining() if enforce_cooldown else 0.0
        if remaining > 0:
            raise TrainingRefused(
                f"Models were trained recently; try again in {math.ceil(remaining)} s.",
                429,
                retry_after=math.ceil(remaining),
            )
        ticket = _GateTicket()
        try:
            yield ticket
        finally:
            cooldown = config.RETRAIN_COOLDOWN_SECONDS if ticket.cooldown is None else ticket.cooldown
            _next_allowed = time.monotonic() + max(0.0, cooldown)
    finally:
        _train_lock.release()


# ── training data hygiene ────────────────────────────────────────────────


def _parse_ts(value: Any) -> Optional[pd.Timestamp]:
    try:
        ts = pd.to_datetime(value, utc=True)
    except (ValueError, TypeError):
        return None
    return None if pd.isna(ts) else ts


def _in_open_incident(event: Dict[str, Any], windows: List[Dict[str, Any]]) -> bool:
    ts = _parse_ts(event.get("timestamp"))
    for w in windows:
        if w["device_id"] != event.get("device_id"):
            continue
        if w["source_ip"] and w["source_ip"] != event.get("source_ip"):
            continue
        if ts is None or w["first"] is None or w["last"] is None:
            return True  # cannot place it: leave it out of training
        if w["first"] <= ts <= w["last"]:
            return True
    return False


def cap_device_share(
    events: List[Dict[str, Any]], max_share: float
) -> Tuple[List[Dict[str, Any]], int]:
    """Keep each device's most recent events, at most *max_share* of the result.

    Only applies with two or more devices. Returns ``(kept, dropped_count)``.
    """
    by_device: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        by_device.setdefault(str(ev.get("device_id", "")), []).append(ev)
    if len(by_device) < 2 or max_share >= 1.0:
        return events, 0

    counts = sorted(len(v) for v in by_device.values())
    # Largest per-device cap c with c <= max_share * sum(min(n_i, c)).
    lo, hi = 1, counts[-1]
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid <= max_share * sum(min(n, mid) for n in counts):
            lo = mid
        else:
            hi = mid - 1
    cap = lo

    kept: List[Dict[str, Any]] = []
    for evs in by_device.values():
        kept.extend(evs[-cap:])  # events arrive oldest first: keep the newest
    kept.sort(key=lambda e: e.get("id", 0))
    return kept, len(events) - len(kept)


def select_training_events(
    max_events: Optional[int] = None, max_share: Optional[float] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Recent events that are safe to learn "normal" from, plus selection stats."""
    from lsadra.storage.database import get_open_incident_windows, get_training_events

    max_events = max_events or config.TRAINING_MAX_EVENTS
    max_share = config.TRAINING_MAX_DEVICE_SHARE if max_share is None else max_share

    events, excluded_anomalies = get_training_events(max_events)

    windows = [
        {
            "device_id": w.get("device_id"),
            "source_ip": w.get("source_ip") or "",
            "first": _parse_ts(w.get("first_seen")),
            "last": _parse_ts(w.get("last_seen")),
        }
        for w in get_open_incident_windows()
    ]
    if windows:
        kept = [e for e in events if not _in_open_incident(e, windows)]
        excluded_incidents = len(events) - len(kept)
        events = kept
    else:
        excluded_incidents = 0

    events, capped = cap_device_share(events, max_share)

    timestamps = [t for t in (_parse_ts(e.get("timestamp")) for e in events) if t is not None]
    per_device: Dict[str, int] = {}
    for e in events:
        per_device[str(e.get("device_id", ""))] = per_device.get(str(e.get("device_id", "")), 0) + 1

    stats = {
        "event_count": len(events),
        "device_count": len(per_device),
        "events_per_device": per_device,
        "excluded_anomalies": excluded_anomalies,
        "excluded_open_incidents": excluded_incidents,
        "excluded_device_cap": capped,
        "excluded_count": excluded_anomalies + excluded_incidents + capped,
        "max_device_share": max_share,
        "window_start": min(timestamps).isoformat() if timestamps else None,
        "window_end": max(timestamps).isoformat() if timestamps else None,
    }
    return events, stats


def describe_frame(df: pd.DataFrame) -> Dict[str, Any]:
    """Selection stats for a caller-supplied training frame (no hygiene applied)."""
    stats: Dict[str, Any] = {"event_count": int(len(df)), "hygiene": "not applied (caller data)"}
    if "device_id" in df.columns:
        stats["device_count"] = int(df["device_id"].nunique())
    if "timestamp" in df.columns and len(df):
        ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True).dropna()
        if len(ts):
            stats["window_start"] = ts.min().isoformat()
            stats["window_end"] = ts.max().isoformat()
    return stats


# ── canary gate ──────────────────────────────────────────────────────────


@lru_cache(maxsize=8)
def _canary_frame(scenario: str) -> Optional[Tuple[pd.DataFrame, Tuple[bool, ...]]]:
    """Feature rows and attack labels for one demo-corpus scenario (cached)."""
    from lsadra.features.feature_extractor import build_features

    path = Path(config.PROJECT_ROOT) / "demo" / "corpus" / f"{scenario}.jsonl"
    if not path.is_file():
        return None
    rows, labels = [], []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        ev = json.loads(line)
        truth = (ev.get("attributes") or {}).get("ground_truth") or {}
        rows.append({
            "id": i,
            "timestamp": ev["timestamp"],
            "device_id": "canary",
            "user_id": "canary",
            "host": ev.get("host", ""),
            "effective_username": ev.get("effective_username", ""),
            "source_ip": ev.get("source_ip") or "",
            "event_type": ev["event_type"],
            "raw_message": ev.get("raw_message", ""),
        })
        labels.append(truth.get("label", "benign") != "benign")
    df = build_features(rows)
    if df.empty or len(df) != len(labels):
        return None
    return df, tuple(labels)


def run_canary(
    ensemble: Any,
    autoencoder: Any,
    scenarios: Optional[List[str]] = None,
    min_recall: Optional[float] = None,
) -> Dict[str, Any]:
    """Check that a candidate's ML layers still flag the known attack scenarios.

    Recall per scenario = attack events flagged by the ensemble or the
    autoencoder / attack events. Every scenario must reach *min_recall*.
    A missing scenario fails the canary (fail closed). ``min_recall <= 0``
    disables the gate explicitly.
    """
    scenarios = list(config.CANARY_SCENARIOS if scenarios is None else scenarios)
    min_recall = config.CANARY_MIN_RECALL if min_recall is None else min_recall
    result: Dict[str, Any] = {"min_recall": min_recall, "scenarios": {}, "passed": True}
    if min_recall <= 0:
        result["note"] = "canary disabled (LSADRA_CANARY_MIN_RECALL <= 0)"
        return result
    if not scenarios:
        result.update(passed=False, note="no canary scenarios configured")
        return result

    for name in scenarios:
        frame = _canary_frame(name)
        if frame is None:
            result["scenarios"][name] = {"error": "scenario not found"}
            result["passed"] = False
            continue
        df, labels = frame
        l2 = ensemble.predict(df)
        l3 = autoencoder.score(df)
        attacks = [i for i, is_attack in enumerate(labels) if is_attack]
        flagged = sum(
            1 for i in attacks if l2[i].get("is_anomaly") or l3[i].get("is_ae_anomaly")
        )
        recall = flagged / len(attacks) if attacks else 1.0
        ok = recall >= min_recall
        result["scenarios"][name] = {
            "attack_events": len(attacks),
            "flagged": flagged,
            "recall": round(recall, 4),
            "passed": ok,
        }
        result["passed"] = result["passed"] and ok
    return result


# ── drift reference (G-19) ───────────────────────────────────────────────


def reference_quantiles(df: pd.DataFrame, n_bins: int = 10) -> Dict[str, Any]:
    """Per-feature bin edges and proportions of the training data, for PSI."""
    feats: Dict[str, Any] = {}
    for feat in FEATURE_COLS:
        if feat not in df.columns:
            continue
        values = pd.to_numeric(df[feat], errors="coerce").dropna().to_numpy(dtype=float)
        if len(values) < 10:
            continue
        edges = np.unique(np.percentile(values, np.linspace(0, 100, n_bins + 1)))
        if len(edges) < 2:
            continue
        counts, _ = np.histogram(values, bins=edges)
        feats[feat] = {
            "edges": [float(x) for x in edges],
            "proportions": [float(c) / len(values) for c in counts],
            "n": int(len(values)),
        }
    return {"created_at": datetime.now(timezone.utc).isoformat(), "features": feats}


def psi_against_reference(ref: Dict[str, Any], values: np.ndarray) -> float:
    """PSI of *values* against a stored reference; out-of-range values count in the end bins."""
    eps = 1e-6
    edges = np.asarray(ref["edges"], dtype=float)
    ref_pct = np.asarray(ref["proportions"], dtype=float) + eps
    clipped = np.clip(values, edges[0], edges[-1])
    counts, _ = np.histogram(clipped, bins=edges)
    cur_pct = counts / max(len(values), 1) + eps
    return max(float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct))), 0.0)


def load_reference(directory: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    try:
        return current_store(directory).load_json(REFERENCE_FILE)
    except (ModelIntegrityError, ValueError, OSError) as exc:
        logger.info("No verified drift reference: %s", exc)
        return None


# ── model cards (G-19) ───────────────────────────────────────────────────


def library_versions() -> Dict[str, str]:
    from lsadra import __version__

    versions = {"lsadra": __version__, "python": platform.python_version()}
    for mod in ("numpy", "pandas", "sklearn", "joblib", "torch"):
        try:
            versions[mod] = __import__(mod).__version__
        except Exception:  # noqa: BLE001 - optional dependency
            continue
    return versions


_MODEL_DESCRIPTIONS = {
    "ensemble": {
        "type": "Isolation Forest + Local Outlier Factor + One-Class SVM, majority vote",
        "format": "joblib (scikit-learn pickle), verified against the signed manifest",
        "file": ENSEMBLE_FILE,
    },
    "autoencoder": {
        "type": "Feed-forward autoencoder, 95th-percentile reconstruction error threshold",
        "format": "torch state dict, tensors only, loaded with weights_only=True",
        "file": AUTOENCODER_FILE,
    },
    "baseline": {
        "type": "Per user and device rolling z-score baseline",
        "format": "plain JSON",
        "file": BASELINE_FILE,
    },
    "ecod": {
        "type": "ECOD empirical-CDF tail scorer, shadow mode (reported, never alerts)",
        "format": "plain JSON (distinct values and cumulative counts per feature)",
        "file": ECOD_FILE,
        "features": "model",
    },
}


def build_model_card(
    model_name: str,
    version: Optional[int],
    sha256: Optional[str],
    selection: Dict[str, Any],
    canary: Dict[str, Any],
    trigger: str,
) -> Dict[str, Any]:
    desc = _MODEL_DESCRIPTIONS[model_name]
    return {
        "model": model_name,
        "version": version,
        "type": desc["type"],
        "file": desc["file"],
        "format": desc["format"],
        "sha256": sha256,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "trigger": trigger,
        "features": list(MODEL_FEATURE_NAMES) if desc.get("features") == "model" else list(FEATURE_COLS),
        "training_data": {
            k: selection.get(k)
            for k in (
                "event_count",
                "device_count",
                "window_start",
                "window_end",
                "excluded_anomalies",
                "excluded_open_incidents",
                "excluded_device_cap",
                "max_device_share",
                "hygiene",
            )
            if k in selection
        },
        "canary": canary,
        "library_versions": library_versions(),
        "intended_use": "Unsupervised anomaly scoring of authentication events on hosts the "
        "operator owns. Scores support, and never replace, analyst review.",
        "limitations": "Learns from the operator's own recent events, so it inherits whatever "
        "they contain; sees the nine V3 features only; no labelled evaluation yet "
        "(see ADR 0007 and the detection bench).",
    }


def read_cards(directory: Optional[Path] = None) -> Dict[str, Any]:
    store = current_store(directory)
    cards: Dict[str, Any] = {}
    for name in MODEL_NAMES:
        try:
            cards[name] = store.load_json(card_file(name))
        except (ModelIntegrityError, ValueError, OSError):
            cards[name] = None
    return cards
