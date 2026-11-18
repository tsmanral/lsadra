"""
LSADRA V3 — Detection orchestrator (pipeline).

Runs the full detection stack:
  1. Baselining check (skip ML for devices below MIN_BASELINE_EVENTS)
  2. Statistical baseline (Rolling Z-Score)
  3. Ensemble ML models (majority vote)
  4. Autoencoder
  5. Severity scoring
  6. Rules + MITRE mapping
  7. SHAP explainability
  8. Narrative generation
  9. Incident management (grouping)
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

import pandas as pd

from lsadra.config import (
    DETECTION_THROTTLE_SECONDS,
    MIN_BASELINE_EVENTS,
    MODEL_DIR,
)
from lsadra.detection.incident_manager import IncidentManager
from lsadra.detection.severity import apply_rule_floor, compute_severity_score, severity_context
from lsadra.features.feature_extractor import FEATURE_COLS, build_features
from lsadra.features.rule_features import RULE_LOOKBACK_MINUTES, build_rule_features
from lsadra.models.autoencoder_model import AutoencoderModel
from lsadra.models.ensemble_model import EnsembleModel
from lsadra.models.statistical_baseline import StatisticalBaselineModel
from lsadra.session.session_builder import SessionBuilder
from lsadra.session.user_profile_store import UserProfileStore
from lsadra.storage.database import (
    get_device,
    get_event_count_for_device,
    get_events_before,
    get_events_since,
    get_watermark,
    increment_device_event_count,
    insert_anomaly,
    insert_sigma_matches,
    register_model,
    set_watermark,
    update_device_status,
)
from lsadra.ui.alert_stream import alert_hub

logger = logging.getLogger(__name__)


class DetectionOrchestrator:
    """
    Central orchestration for all detection layers.

    Supports model persistence: loads from disk on init, saves after training.
    Respects the MIN_BASELINE_EVENTS threshold before running ML detection.
    """

    def __init__(self) -> None:
        self.baseline = StatisticalBaselineModel()
        self.ensemble = EnsembleModel()
        self.autoencoder = AutoencoderModel()
        self.session_builder = SessionBuilder()
        self.profile_store = UserProfileStore()
        self.incident_manager = IncidentManager()
        self._last_run: Dict[str, float] = {}  # device_id → timestamp of last run
        self._trained = False

        # Attempt to load persisted models
        self._load_models()

    def _load_models(self) -> None:
        """Try to load persisted models from disk (cold start)."""
        try:
            ensemble_path = MODEL_DIR / "ensemble.joblib"
            if ensemble_path.exists():
                self.ensemble = EnsembleModel.load(ensemble_path)
                self._trained = True
                logger.info("Loaded persisted ensemble model.")
        except Exception:
            logger.info("No persisted ensemble found — will train from scratch.")

        try:
            if self.autoencoder.load():
                logger.info("Loaded persisted autoencoder model.")
        except Exception:
            logger.info("No persisted autoencoder found — will train from scratch.")

    # ── train (batch pre-load) ────────────────────────────────────────────

    def train(self, df: pd.DataFrame) -> None:
        """
        Train all model layers on historical baseline data.

        Args:
            df: DataFrame with feature columns (output of ``build_features``).
        """
        self.baseline.train(df)
        self.ensemble.train(df)
        self.autoencoder.train(df)
        self._trained = True
        logger.info("DetectionOrchestrator: all layers trained.")

        # Persist models
        self._save_models(event_count=len(df))

    def _save_models(self, event_count: int = 0) -> None:
        """Save all trained models and register them in the DB."""
        try:
            path = self.ensemble.save()
            register_model("ensemble", "ensemble", str(path), event_count)
        except Exception:
            logger.exception("Failed to save ensemble model.")

        try:
            path = self.autoencoder.save()
            register_model("autoencoder", "autoencoder", str(path), event_count)
        except Exception:
            logger.exception("Failed to save autoencoder model.")

    # ── online mode ───────────────────────────────────────────────────────

    def run_for_new_events(self, device_id: str) -> None:
        """
        Near-real-time detection for freshly ingested events.

        Throttled to at most once per ``DETECTION_THROTTLE_SECONDS`` per device.
        Skips ML detection for devices still in BASELINING phase.
        Auto-trains models when a device crosses the baseline threshold.
        """
        now = time.time()
        last = self._last_run.get(device_id, 0.0)
        if now - last < DETECTION_THROTTLE_SECONDS:
            return
        self._last_run[device_id] = now

        watermark = get_watermark(device_id)
        new_events = get_events_since(device_id, after_id=watermark)
        if not new_events:
            return

        logger.info("Online detection: %d new events for device %s", len(new_events), device_id)

        # Track event count and check baselining status
        event_total = increment_device_event_count(device_id, len(new_events))

        # Build features over the new events plus the device's recent history,
        # so 5/15/30-minute windows span detection runs (a slow attack split
        # across several runs still crosses its threshold). History rows are
        # context only: they are never scored or alerted on twice.
        context = self._context_events(device_id, new_events)
        df = build_features(context + new_events)
        if df.empty:
            return
        context_ids = {ev.get("id") for ev in context}
        df["_context_only"] = df["id"].isin(context_ids) if context_ids else False

        # Update user profile
        user_id = new_events[0].get("user_id", "")
        self.profile_store.update(user_id, new_events)

        # Check if device is still baselining
        if event_total < MIN_BASELINE_EVENTS:
            logger.info(
                "Device %s is BASELINING (%d/%d events) — storing events only.",
                device_id, event_total, MIN_BASELINE_EVENTS,
            )
            # Update watermark but skip detection
            max_id = max(ev.get("id", 0) for ev in new_events)
            set_watermark(device_id, max_id)
            return

        # Transition from BASELINING to ONLINE if just crossed threshold
        device = get_device(device_id)
        if device and device.get("status") == "BASELINING":
            update_device_status(device_id, "ONLINE")
            logger.info("Device %s transitioned from BASELINING -> ONLINE.", device_id)

            # Auto-train on all historical events for this device
            if not self._trained:
                self._auto_train(device_id)

        # If models still aren't trained, try training now
        if not self._trained:
            self._auto_train(device_id)

        # Run full detection pipeline
        results = self._run_layers(df)

        # Record Sigma matches (shadow and alert mode alike), so the bench and
        # analysts can compare the layer with the built-in rules.
        sigma_rows = [r for r in results if r.get("sigma_matches")]
        if sigma_rows:
            try:
                insert_sigma_matches(sigma_rows)
            except Exception:
                logger.exception("Could not store Sigma matches for device %s", device_id)

        # Persist anomalies and create incidents
        for res in results:
            if res.get("is_anomaly"):
                anomaly_id = insert_anomaly(res)
                res["anomaly_id"] = anomaly_id
                # Process through incident manager
                res["incident_id"] = self.incident_manager.process_anomaly(res)
                alert_hub.publish(res)  # /ws/alerts; never raises

        # Update watermark
        max_id = max(ev.get("id", 0) for ev in new_events)
        set_watermark(device_id, max_id)

    @staticmethod
    def _context_events(device_id: str, new_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Stored events from the RULE_LOOKBACK_MINUTES before the new batch."""
        first_id = min(int(ev.get("id", 0) or 0) for ev in new_events)
        stamps = [str(ev.get("timestamp") or "") for ev in new_events if ev.get("timestamp")]
        if not stamps or first_id <= 1:
            return []
        try:
            start = pd.to_datetime(min(stamps), utc=True)
        except (ValueError, TypeError):
            return []
        since = (start - pd.Timedelta(minutes=RULE_LOOKBACK_MINUTES)).strftime("%Y-%m-%dT%H:%M:%S")
        try:
            return get_events_before(device_id, before_id=first_id, since=since)
        except Exception:
            logger.exception("Could not load detection context for device %s", device_id)
            return []

    def _auto_train(self, device_id: str) -> None:
        """Auto-train models on all historical events for a device."""
        try:
            all_events = get_events_since(device_id, after_id=0)
            if len(all_events) < MIN_BASELINE_EVENTS:
                return
            train_df = build_features(all_events)
            if train_df.empty:
                return
            logger.info("Auto-training models on %d events from device %s", len(train_df), device_id)
            self.train(train_df)
            logger.info("Auto-training complete. Models are now active.")
        except Exception:
            logger.exception("Auto-training failed for device %s", device_id)


    # ── batch mode ────────────────────────────────────────────────────────

    def run_batch(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Full-dataset evaluation for benchmarking.

        Returns a list of detection result dicts (one per row).
        """
        return self._run_layers(df)

    # ── private layer pipeline ────────────────────────────────────────────

    def _run_layers(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Execute all detection layers, score severity, and merge verdicts."""
        from lsadra.detection.rule_engine import (
            _LEVEL_TO_SEVERITY,
            NO_RULE_MATCH,
            UNMAPPED_ANOMALY,
            evaluate,
        )
        from lsadra.detection.sigma_engine import get_engine, sigma_mode
        from lsadra.explainability.narrative_builder import NarrativeBuilder

        # Rule features are computed over context rows too (that is what the
        # context is for); only the rest are scored.
        df = build_rule_features(df)

        # Sigma layer: sees the whole frame (correlation rules need the
        # context rows); hits are kept for scored rows only.
        sigma = get_engine()
        mode = sigma_mode() if sigma is not None else "off"
        sigma_hits: List[List[Any]] = [[] for _ in range(len(df))]
        if sigma is not None and len(df):
            try:
                scored = (~df["_context_only"].astype(bool)).tolist() \
                    if "_context_only" in df.columns else None
                sigma_hits = sigma.evaluate_frame(df.to_dict("records"), scored=scored)
            except Exception:
                logger.exception("Sigma layer failed on this frame; continuing without it")
        if "_context_only" in df.columns:
            keep = ~df["_context_only"].astype(bool)
            sigma_hits = [h for h, k in zip(sigma_hits, keep.tolist()) if k]
            df = df[keep].reset_index(drop=True)

        n = len(df)
        if n == 0:
            return []

        # Layer 1 — statistical baseline
        l1 = self.baseline.score(df)

        # Layer 2 — ensemble
        if self._trained:
            l2 = self.ensemble.predict(df)
        else:
            l2 = [{"is_anomaly": False, "anomaly_score": 0.0, "votes": 0, "total_models": 3}] * n

        # Layer 3 — autoencoder
        l3 = self.autoencoder.score(df)

        # Merge and apply Layer 4 (rules + narrative + severity)
        merged: List[Dict[str, Any]] = []
        for i in range(n):
            row = df.iloc[i]

            is_anomaly = (
                l1[i].get("is_baseline_anomaly", False)
                or l2[i].get("is_anomaly", False)
                or l3[i].get("is_ae_anomaly", False)
            )

            # Rules (lsadra/detection/rule_engine.py). A match at medium level or
            # above raises an alert on its own and names the technique; a low
            # match only names the technique of an anomaly layers 1-3 flagged.
            # An ML-only anomaly is reported without an ATT&CK technique rather
            # than with a guessed one.
            row_dict = row.to_dict()
            matches = evaluate(row_dict)
            best = matches[0] if matches else None
            if best is not None and best.raises_alert:
                is_anomaly = True
            if is_anomaly and best is not None:
                threat_type, mitre_id = best.rule.title, best.technique.id
            elif is_anomaly:
                threat_type, mitre_id = UNMAPPED_ANOMALY
            else:
                threat_type, mitre_id = NO_RULE_MATCH
            labelled = is_anomaly and best is not None

            # Sigma in alert mode: a medium+ match raises an alert, and names
            # the technique when no built-in rule did. In shadow mode its
            # matches are only recorded (``sigma_matches``).
            hits = sigma_hits[i]
            top_sigma = hits[0] if hits else None
            sigma_labelled = False
            if mode == "alert" and top_sigma is not None and not labelled:
                if top_sigma.raises_alert:
                    is_anomaly = True
                if is_anomaly and top_sigma.technique_ids:
                    threat_type, mitre_id = top_sigma.title, top_sigma.technique_ids[0]
                    sigma_labelled = True

            # Compute severity
            layer1_z = l1[i].get("z_max", 0.0)
            layer2_score = l2[i].get("anomaly_score", 0.0)
            layer2_votes = l2[i].get("votes", 0)
            total_models = l2[i].get("total_models", 3)
            layer3_error = l3[i].get("reconstruction_error", 0.0)

            severity_score, severity_label = compute_severity_score(
                layer1_z=layer1_z,
                layer2_score=layer2_score,
                layer2_votes=layer2_votes,
                total_models=total_models,
                layer3_error=layer3_error,
            )
            if labelled:
                severity_score, severity_label = apply_rule_floor(
                    severity_score, severity_label, best.severity)
            elif sigma_labelled:
                severity_score, severity_label = apply_rule_floor(
                    severity_score, severity_label, _LEVEL_TO_SEVERITY.get(top_sigma.level))

            # Build narrative
            narrative = ""
            shap_values = {}
            if is_anomaly:
                sev_ctx = severity_context(severity_score, severity_label)
                narrative = NarrativeBuilder.build(
                    threat_type=threat_type,
                    mitre_id=mitre_id,
                    row_data=row_dict,
                    layer1_z=layer1_z,
                    layer2_score=layer2_score,
                    layer3_error=layer3_error,
                    severity_context=sev_ctx,
                )

            merged.append({
                "event_id": int(row.get("id", 0)),
                "device_id": str(row.get("device_id", "")),
                "user_id": str(row.get("user_id", "")),
                "source_ip": str(row.get("source_ip", "")),
                "layer1_score": layer1_z,
                "layer2_score": layer2_score,
                "layer2_votes": layer2_votes,
                "layer3_score": layer3_error,
                "severity_score": severity_score,
                "severity_label": severity_label,
                "is_anomaly": is_anomaly,
                "threat_type": threat_type,
                "attack_type": threat_type,  # normalized key for incident grouping
                "mitre_technique": mitre_id,
                # The matched rule's author-set confidence; 0 when no rule
                # named the technique.
                "mitre_confidence": best.rule.confidence if labelled else 0.0,
                "mitre_tactics": (best.tactics if labelled
                                  else list(top_sigma.tactics) if sigma_labelled else []),
                "rule_id": (best.rule.id if labelled
                            else f"sigma:{top_sigma.rule_id}" if sigma_labelled else None),
                "rule_version": best.rule.version if labelled else None,
                "rule_level": (best.level if labelled
                               else top_sigma.level if sigma_labelled else None),
                "rule_reason": best.reason if labelled else "",
                "rule_matches": [m.rule.id for m in matches],
                "sigma_mode": mode,
                "sigma_matches": [h.as_dict() for h in hits],
                "narrative": narrative,
                "shap_values": shap_values,
                "is_synthetic": bool(row.get("is_synthetic", False)),
                "created_at": str(row.get("timestamp", "")),
            })

        return merged
