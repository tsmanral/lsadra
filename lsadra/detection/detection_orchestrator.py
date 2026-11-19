"""
LSADRA V3 — Detection orchestrator (pipeline).

Runs the full detection stack:
  1. Baselining check (skip ML for devices below MIN_BASELINE_EVENTS)
  2. Statistical baseline (Rolling Z-Score)
  3. Ensemble ML models (majority vote)
  4. Autoencoder
  5. Severity scoring
  6. Rules + MITRE mapping
  7. (SHAP explainability is not wired in: shap_values stays empty)
  8. Narrative generation
  9. Incident management (grouping)
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from lsadra import config
from lsadra.config import (
    DETECTION_THROTTLE_SECONDS,
    MIN_BASELINE_EVENTS,
)
from lsadra.detection import model_lifecycle as lifecycle
from lsadra.detection.incident_manager import IncidentManager
from lsadra.detection.severity import apply_rule_floor, compute_severity_score, severity_context
from lsadra.features.feature_extractor import FEATURE_COLS, build_features
from lsadra.features.model_features import model_feature_matrix
from lsadra.features.rule_features import RULE_LOOKBACK_MINUTES, build_rule_features
from lsadra.models.autoencoder_model import AutoencoderModel
from lsadra.models.ecod_model import ECODModel
from lsadra.models.ensemble_model import EnsembleModel
from lsadra.models.integrity import ModelIntegrityError
from lsadra.models.statistical_baseline import StatisticalBaselineModel
from lsadra.session.session_builder import SessionBuilder
from lsadra.session.user_profile_store import UserProfileStore
from lsadra.storage.database import (
    get_device,
    get_event_count_for_device,
    get_events_before,
    get_events_since,
    get_latest_model,
    get_watermark,
    increment_device_event_count,
    insert_anomaly,
    insert_sigma_matches,
    insert_training_run,
    register_model,
    set_watermark,
    update_device_status,
)
from lsadra.ui.alert_stream import alert_hub

logger = logging.getLogger(__name__)

# A batch that fails this many times in a row is skipped (watermark advanced)
# so one bad batch can never stop detection for its device for good.
MAX_BATCH_FAILURES = 3


class DetectionOrchestrator:
    """
    Central orchestration for all detection layers.

    Supports model persistence: loads from disk on init, saves after training.
    Respects the MIN_BASELINE_EVENTS threshold before running ML detection.
    """

    # Model generation this instance loaded. None (also the class default, for
    # instances built without __init__ whose layers are injected) never reloads.
    _generation: Optional[int] = None

    def __init__(self, model_dir: Optional[Path] = None) -> None:
        self.model_dir = Path(model_dir) if model_dir else lifecycle.model_dir()
        self.baseline = StatisticalBaselineModel()
        self.ensemble = EnsembleModel()
        self.autoencoder = AutoencoderModel()
        self.session_builder = SessionBuilder()
        self.profile_store = UserProfileStore()
        self.incident_manager = IncidentManager()
        self._last_run: Dict[str, float] = {}  # device_id → timestamp of last run
        self._batch_failures: Dict[str, int] = {}  # device_id → consecutive failed runs
        self._trained = False
        self._generation = None
        self._trained_on: Optional[int] = None   # usable events behind the live models
        self._growth_base: Optional[int] = None  # event clock at the last training run

        # Attempt to load persisted models
        self._load_models()

    # ── persistence ───────────────────────────────────────────────────────

    def _load_models(self) -> None:
        """Load persisted models from disk (cold start, after a swap or a rollback).

        Every file is verified against the folder's authenticated manifest
        before it is deserialized (G-17). Anything that does not verify is
        skipped and the models retrain.
        """
        self._generation = lifecycle.generation()
        store = lifecycle.current_store(self.model_dir)

        try:
            ensemble = store.load_joblib(lifecycle.ENSEMBLE_FILE)
            if not isinstance(ensemble, EnsembleModel):
                raise TypeError("ensemble file holds an unexpected type")
            self.ensemble = ensemble
            self._trained = True
            logger.info("Loaded persisted ensemble model.")
            self._note_trained_on(_card_event_count(store))
        except ModelIntegrityError as exc:
            self.ensemble = EnsembleModel()
            self._trained = False
            if (self.model_dir / lifecycle.ENSEMBLE_FILE).exists():
                logger.warning("Not loading the persisted ensemble: %s. Models will retrain.", exc)
            else:
                logger.info("No persisted ensemble found — will train from scratch.")
        except Exception:
            self.ensemble = EnsembleModel()
            self._trained = False
            logger.exception("Failed to load the persisted ensemble — will train from scratch.")

        self.shadow_ecod = None
        if (self.model_dir / lifecycle.ECOD_FILE).exists():
            try:
                self.shadow_ecod = ECODModel.from_dict(store.load_json(lifecycle.ECOD_FILE))
                logger.info("Loaded the ECOD shadow scorer.")
            except (ModelIntegrityError, ValueError, KeyError, OSError) as exc:
                logger.warning("Not loading the ECOD shadow scorer: %s", exc)

        autoencoder = AutoencoderModel()
        if autoencoder.load(self.model_dir / lifecycle.AUTOENCODER_FILE):
            logger.info("Loaded persisted autoencoder model.")
        elif self._trained:
            # e.g. an install upgraded from the PyTorch autoencoder.pt format:
            # retrain once rather than run without the autoencoder layer.
            logger.warning("Ensemble loaded but no usable autoencoder — models will retrain.")
            self._trained = False
        self.autoencoder = autoencoder

        try:
            self.baseline = StatisticalBaselineModel.from_dict(
                store.load_json(lifecycle.BASELINE_FILE)
            )
            logger.info("Loaded per-entity baselines (%d entities).", len(self.baseline._profiles))
        except (ModelIntegrityError, ValueError, OSError) as exc:
            self.baseline = StatisticalBaselineModel()
            logger.info("No verified per-entity baselines: %s", exc)

    def _reload_if_swapped(self) -> None:
        """Pick up models another orchestrator in this process promoted or rolled back."""
        if self._generation is not None and self._generation != lifecycle.generation():
            logger.info("Model files changed in this process — reloading.")
            self._load_models()

    # ── train (batch pre-load) ────────────────────────────────────────────

    def train(
        self,
        df: pd.DataFrame,
        *,
        trigger: str = "other",
        requested_by: Optional[str] = None,
        selection: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Fit a candidate on *df*, gate it with the canary, and promote it if it passes.

        The live models keep serving until promotion. A rejected candidate is
        discarded and recorded. Returns a summary with ``status`` (``promoted``
        or ``rejected``), the canary result and the training selection.

        Args:
            df: DataFrame with feature columns (output of ``build_features``).
        """
        selection = selection or lifecycle.describe_frame(df)

        cand_baseline = StatisticalBaselineModel()
        cand_ensemble = EnsembleModel()
        cand_autoencoder = AutoencoderModel()
        cand_baseline.train(df)
        cand_ensemble.train(df)
        cand_autoencoder.train(df)
        cand_ecod = fit_shadow_ecod(df)

        canary = lifecycle.run_canary(cand_ensemble, cand_autoencoder)
        summary: Dict[str, Any] = {
            "status": "promoted" if canary["passed"] else "rejected",
            "events": int(len(df)),
            "canary": canary,
            "selection": selection,
        }
        if not canary["passed"]:
            logger.warning(
                "Candidate models rejected by the canary (%s); keeping the current models.",
                json.dumps(canary.get("scenarios", {})),
            )
            self._record_run(trigger, requested_by, "rejected", selection, canary,
                             "candidate no longer flags the canary attack scenarios")
            return summary

        self._promote(df, cand_baseline, cand_ensemble, cand_autoencoder,
                      selection, canary, trigger, ecod=cand_ecod)
        self._record_run(trigger, requested_by, "promoted", selection, canary, "")
        logger.info("DetectionOrchestrator: candidate promoted; all layers active.")
        return summary

    def _promote(
        self,
        df: pd.DataFrame,
        baseline: StatisticalBaselineModel,
        ensemble: EnsembleModel,
        autoencoder: AutoencoderModel,
        selection: Dict[str, Any],
        canary: Dict[str, Any],
        trigger: str,
        ecod: Optional[ECODModel] = None,
    ) -> None:
        """Snapshot the current files to previous/, write the candidate, swap it in."""
        store = lifecycle.current_store(self.model_dir)
        previous = lifecycle.previous_store(self.model_dir)
        if store.entries():
            store.copy_verified_to(previous)

        try:
            ensemble.save(self.model_dir / lifecycle.ENSEMBLE_FILE)
            if autoencoder.is_fitted:
                autoencoder.save(self.model_dir / lifecycle.AUTOENCODER_FILE)
            else:
                store.remove(lifecycle.AUTOENCODER_FILE)
            store.save_json(lifecycle.BASELINE_FILE, baseline.to_dict())
            if ecod is not None:
                store.save_json(lifecycle.ECOD_FILE, ecod.to_dict())
            else:
                store.remove(lifecycle.ECOD_FILE)
            store.save_json(lifecycle.REFERENCE_FILE, lifecycle.reference_quantiles(df))
            self._register_and_card(store, selection, canary, trigger)
        except Exception:
            logger.exception("Writing the promoted models failed — restoring the previous files.")
            if previous.entries():
                previous.copy_verified_to(store)
            raise

        self.baseline = baseline
        self.ensemble = ensemble
        self.autoencoder = autoencoder
        self.shadow_ecod = ecod
        self._trained = True
        self._generation = lifecycle.bump_generation()
        self._note_trained_on(int(selection.get("event_count", 0) or len(df)))

    def _register_and_card(
        self,
        store: Any,
        selection: Dict[str, Any],
        canary: Dict[str, Any],
        trigger: str,
    ) -> None:
        """Register each model version and write its model card (G-19)."""
        files = {
            "ensemble": lifecycle.ENSEMBLE_FILE,
            "autoencoder": lifecycle.AUTOENCODER_FILE,
            "baseline": lifecycle.BASELINE_FILE,
            "ecod": lifecycle.ECOD_FILE,
        }
        for name, fname in files.items():
            sha = store.sha256(fname)
            if sha is None:
                continue
            version = None
            try:
                register_model(
                    name, name, str(self.model_dir / fname),
                    int(selection.get("event_count", 0)),
                    metrics={"sha256": sha, "canary_passed": bool(canary.get("passed"))},
                )
                latest = get_latest_model(name)
                version = latest.get("version") if latest else None
            except Exception:
                logger.exception("Failed to register model %s.", name)
            card = lifecycle.build_model_card(name, version, sha, selection, canary, trigger)
            store.save_json(lifecycle.card_file(name), card)

    @staticmethod
    def _record_run(
        trigger: str,
        requested_by: Optional[str],
        status: str,
        selection: Dict[str, Any],
        canary: Optional[Dict[str, Any]],
        detail: str,
    ) -> None:
        if trigger == "auto" and status == "skipped":
            return  # waiting for enough data is not worth an audit row every 30 s
        try:
            insert_training_run(
                trigger, requested_by, status,
                event_count=int(selection.get("event_count", 0) or 0),
                device_count=int(selection.get("device_count", 0) or 0),
                excluded_count=int(selection.get("excluded_count", 0) or 0),
                canary=canary, detail=detail,
            )
        except Exception:
            logger.exception("Failed to record the training run.")

    def retrain(self, trigger: str = "api", requested_by: Optional[str] = None) -> Dict[str, Any]:
        """Train from the database with every G-18 control applied.

        One run at a time and a cooldown between runs (raises
        ``TrainingRefused`` otherwise); events tied to anomalies or open
        incidents are left out and no device supplies more than its share;
        the candidate must pass the canary before it replaces the live models.
        """
        try:
            with lifecycle.training_gate() as ticket:
                events, selection = lifecycle.select_training_events()
                if selection["event_count"] < config.MIN_TRAINING_EVENTS:
                    ticket.cooldown = lifecycle.SKIPPED_RUN_COOLDOWN_SECONDS
                    detail = (f"{selection['event_count']} usable events; "
                              f"{config.MIN_TRAINING_EVENTS} needed")
                    self._record_run(trigger, requested_by, "skipped", selection, None, detail)
                    return {"status": "skipped", "detail": detail, "selection": selection}
                df = build_features(events)
                if df.empty:
                    ticket.cooldown = lifecycle.SKIPPED_RUN_COOLDOWN_SECONDS
                    self._record_run(trigger, requested_by, "skipped", selection, None,
                                     "no features")
                    return {"status": "skipped", "detail": "no features", "selection": selection}
                selection["event_count"] = int(len(df))
                return self.train(df, trigger=trigger, requested_by=requested_by,
                                  selection=selection)
        except lifecycle.TrainingRefused as exc:
            self._record_run(trigger, requested_by, "refused", {}, None, exc.reason)
            raise
        except Exception as exc:
            self._record_run(trigger, requested_by, "failed", {}, None, repr(exc))
            raise

    def rollback(self, requested_by: Optional[str] = None) -> Dict[str, Any]:
        """Swap the live model files with the previous ones and reload them."""
        with lifecycle.training_gate(enforce_cooldown=False):
            store = lifecycle.current_store(self.model_dir)
            previous = lifecycle.previous_store(self.model_dir)
            if not previous.entries():
                self._record_run("rollback", requested_by, "refused", {}, None,
                                 "no previous model to roll back to")
                raise lifecycle.TrainingRefused("There is no previous model to roll back to.", 404)
            staging = lifecycle.ModelStore(self.model_dir / "rollback_staging")
            store.copy_verified_to(staging)
            previous.copy_verified_to(store)
            staging.copy_verified_to(previous)
            staging.clear()
            lifecycle.bump_generation()
            self._load_models()
            self._record_run("rollback", requested_by, "rolled_back", {}, None,
                             "restored the previous model files")
            return {"status": "rolled_back", "trained": self._trained}

    # ── online mode ───────────────────────────────────────────────────────

    def run_for_new_events(self, device_id: str) -> None:
        """
        Near-real-time detection for freshly ingested events.

        Throttled to at most once per ``DETECTION_THROTTLE_SECONDS`` per device.
        Skips ML detection for devices still in BASELINING phase.
        Auto-trains models when a device crosses the baseline threshold.
        """
        self._reload_if_swapped()
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

        # setdefault: tests may build the orchestrator without __init__.
        batch_failures = self.__dict__.setdefault("_batch_failures", {})
        try:
            self._process_new_events(device_id, new_events)
        except Exception:
            failures = batch_failures.get(device_id, 0) + 1
            if failures < MAX_BATCH_FAILURES:
                batch_failures[device_id] = failures
                raise
            # Give up on this batch rather than retrying it forever: every later
            # run would fetch the same events and fail the same way.
            batch_failures.pop(device_id, None)
            max_id = max(ev.get("id", 0) for ev in new_events)
            set_watermark(device_id, max_id)
            logger.error(
                "Online detection failed %d times in a row for device %s; "
                "skipping events up to id %s so detection can continue.",
                failures, device_id, max_id,
            )
            raise
        batch_failures.pop(device_id, None)

    def _process_new_events(self, device_id: str, new_events: List[Dict[str, Any]]) -> None:
        """Score one batch of new events for *device_id* and advance its watermark."""

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
        else:
            self._maybe_growth_retrain(max(int(ev.get("id", 0) or 0) for ev in new_events))

        # Run full detection pipeline
        results = self._run_layers(df)
        _log_shadow(device_id, results)

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
        """Train automatically once a device leaves baselining (all G-18 controls apply).

        Trains on recent events from every device, not only *device_id*, so the
        first device to finish baselining does not define "normal" for all.
        """
        if lifecycle.is_training() or lifecycle.cooldown_remaining() > 0:
            return  # a run is in progress or happened recently; try again later
        try:
            result = self.retrain(trigger="auto")
            logger.info("Auto-training after device %s: %s", device_id, result.get("status"))
        except lifecycle.TrainingRefused as exc:
            logger.debug("Auto-training not started: %s", exc.reason)
        except Exception:
            logger.exception("Auto-training failed for device %s", device_id)

    def _note_trained_on(self, event_count: Optional[int]) -> None:
        """Remember how many events the live models learned from (growth retrain base)."""
        self._trained_on = event_count
        if event_count:
            self._growth_base = max(getattr(self, "_growth_base", None) or 0, event_count)

    def _maybe_growth_retrain(self, event_clock: int) -> None:
        """Retrain once stored events have grown by AUTO_RETRAIN_GROWTH since the last run.

        *event_clock* is the newest event id, a free and monotonic count of
        stored events, so nothing is read from the database until a run is due.
        Only while the live models saw fewer than TRAINING_MAX_EVENTS events.
        The base moves to the clock before every attempt, so a candidate the
        canary rejects is retried only after the next doubling, not every
        cooldown.
        """
        if not growth_retrain_due(event_clock, getattr(self, "_growth_base", None),
                                  getattr(self, "_trained_on", None)):
            return
        if lifecycle.is_training() or lifecycle.cooldown_remaining() > 0:
            return
        self._growth_base = event_clock
        try:
            result = self.retrain(trigger="auto-growth")
            logger.info("Growth retrain at %d stored events: %s", event_clock, result.get("status"))
        except lifecycle.TrainingRefused as exc:
            logger.debug("Growth retrain not started: %s", exc.reason)
        except Exception:
            logger.exception("Growth retrain failed.")

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

        # Shadow (ADR 0007, Phase 1): ECOD over the wider feature set. Its score
        # and verdict are reported next to the live ones and never change them.
        shadow = getattr(self, "shadow_ecod", None)
        if shadow is not None and shadow.is_fitted:
            ls = shadow.predict(model_feature_matrix(df))
        else:
            ls = [{"ecod_score": None, "is_ecod_anomaly": None}] * n

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
                "shadow_ecod_score": ls[i]["ecod_score"],
                "shadow_ecod_anomaly": ls[i]["is_ecod_anomaly"],
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


def _card_event_count(store: Any) -> Optional[int]:
    """Training-set size recorded on the live ensemble's model card, if any."""
    try:
        card = store.load_json(lifecycle.card_file("ensemble"))
        return int(card["training_data"]["event_count"])
    except Exception:
        return None


def growth_retrain_due(event_clock: int, base: Optional[int], trained_on: Optional[int]) -> bool:
    """Whether the stored-event count has outgrown the live models (see ``_maybe_growth_retrain``)."""
    growth = config.AUTO_RETRAIN_GROWTH
    if growth <= 1 or not base or trained_on is None:
        return False
    if trained_on >= config.TRAINING_MAX_EVENTS:
        return False
    return event_clock >= base * growth


def fit_shadow_ecod(df: pd.DataFrame) -> Optional[ECODModel]:
    """Fit the ECOD shadow scorer on a training frame; never blocks training."""
    try:
        return ECODModel(target_fpr=config.SHADOW_ECOD_TARGET_FPR).fit(model_feature_matrix(df))
    except Exception:
        logger.exception("Training the ECOD shadow scorer failed; continuing without it.")
        return None


def _log_shadow(device_id: str, results: List[Dict[str, Any]]) -> None:
    """One line per run when shadow and live verdicts differ (shadow mode, ADR 0007)."""
    scored = [r for r in results if r.get("shadow_ecod_anomaly") is not None]
    if not scored:
        return
    shadow_only = sum(1 for r in scored if r["shadow_ecod_anomaly"] and not r.get("is_anomaly"))
    live_only = sum(1 for r in scored if r.get("is_anomaly") and not r["shadow_ecod_anomaly"])
    both = sum(1 for r in scored if r.get("is_anomaly") and r["shadow_ecod_anomaly"])
    if shadow_only or live_only:
        logger.info(
            "Shadow ECOD on device %s: %d events, both flagged %d, shadow only %d, live only %d.",
            device_id, len(scored), both, shadow_only, live_only,
        )
