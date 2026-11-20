"""
ECOD shadow scorer (ADR 0007, Phase 1).

The scorer itself, its plain-JSON persistence, and shadow mode: it is trained,
signed, reloaded and reported with every result, and it never changes a live
verdict. Data is synthetic (demo corpus, RFC 5737 addresses).
"""

import json

import numpy as np
import pytest

from tests.test_model_lifecycle import _benign_df, _corpus_events, _db, _orchestrator  # noqa: F401


def _rng_matrix(n=400, d=None, seed=0):
    from lsadra.features.model_features import MODEL_FEATURE_NAMES

    d = d or len(MODEL_FEATURE_NAMES)
    return np.random.default_rng(seed).normal(size=(n, d))


class TestECODModel:
    def test_tail_values_score_higher_than_typical(self):
        from lsadra.models.ecod_model import ECODModel

        X = _rng_matrix()
        m = ECODModel().fit(X)
        typical = np.zeros((1, X.shape[1]))
        high, low = typical.copy(), typical.copy()
        high[0, 3] = 8.0
        low[0, 5] = -8.0
        s = m.score(np.vstack([typical, high, low]))
        assert s[1] > s[0] and s[2] > s[0]

    def test_threshold_flags_about_target_share_of_training(self):
        from lsadra.models.ecod_model import ECODModel

        X = _rng_matrix(n=5000)
        m = ECODModel(target_fpr=0.01).fit(X)
        flagged = sum(r["is_ecod_anomaly"] for r in m.predict(X))
        assert flagged <= 0.01 * len(X) + 1

    def test_json_round_trip_scores_identically(self):
        from lsadra.models.ecod_model import ECODModel

        X = _rng_matrix()
        m = ECODModel().fit(X)
        again = ECODModel.from_dict(json.loads(json.dumps(m.to_dict())))
        np.testing.assert_allclose(again.score(X[:50]), m.score(X[:50]))
        assert again.threshold == m.threshold

    def test_rejects_a_file_for_another_feature_set(self):
        from lsadra.models.ecod_model import ECODModel

        data = ECODModel().fit(_rng_matrix()).to_dict()
        data["features"] = data["features"][:-1]
        with pytest.raises(ValueError):
            ECODModel.from_dict(data)

    def test_many_distinct_values_are_compressed(self):
        from lsadra.models.ecod_model import MAX_DISTINCT, ECODModel

        m = ECODModel().fit(_rng_matrix(n=MAX_DISTINCT * 3))
        assert all(len(v) <= MAX_DISTINCT for v in m.values)
        assert m.score(_rng_matrix(n=10, seed=1)).shape == (10,)


def test_model_feature_matrix_has_fixed_width_and_one_hot():
    from lsadra.features.feature_extractor import build_features
    from lsadra.features.model_features import MODEL_FEATURE_NAMES, model_feature_matrix

    evs = _corpus_events("ssh_bruteforce")[:20]
    for i, e in enumerate(evs, 1):
        e["id"] = i
    X = model_feature_matrix(build_features(evs))
    assert X.shape == (20, len(MODEL_FEATURE_NAMES))
    et_cols = [j for j, n in enumerate(MODEL_FEATURE_NAMES) if n.startswith("et_")]
    assert (X[:, et_cols].sum(axis=1) == 1).all()


def test_shadow_is_trained_signed_and_reloaded():
    from lsadra.detection import model_lifecycle as lifecycle

    orch = _orchestrator()
    assert orch.train(_benign_df(), trigger="other")["status"] == "promoted"
    assert orch.shadow_ecod is not None and orch.shadow_ecod.is_fitted
    store = lifecycle.current_store(orch.model_dir)
    assert store.sha256(lifecycle.ECOD_FILE)
    assert lifecycle.read_cards(orch.model_dir)["ecod"]["features"][-1].startswith("et_")

    fresh = _orchestrator()
    assert fresh.shadow_ecod is not None
    df = _benign_df(repeat=1)
    from lsadra.features.model_features import model_feature_matrix

    X = model_feature_matrix(df)
    np.testing.assert_allclose(fresh.shadow_ecod.score(X), orch.shadow_ecod.score(X))


def test_tampered_shadow_file_is_not_loaded():
    from lsadra.detection import model_lifecycle as lifecycle

    orch = _orchestrator()
    orch.train(_benign_df(), trigger="other")
    path = orch.model_dir / lifecycle.ECOD_FILE
    data = json.loads(path.read_text())
    data["threshold"] = 1e9
    path.write_text(json.dumps(data))
    assert _orchestrator().shadow_ecod is None


def test_shadow_never_changes_a_live_verdict():
    orch = _orchestrator()
    orch.train(_benign_df(), trigger="other")
    attack = _corpus_events("ssh_bruteforce")
    for i, e in enumerate(attack, 1):
        e["id"] = 10_000 + i
    from lsadra.features.feature_extractor import build_features

    df = build_features(attack)
    with_shadow = orch._run_layers(df)
    shadow = orch.shadow_ecod
    orch.shadow_ecod = None
    without = orch._run_layers(df)
    orch.shadow_ecod = shadow

    assert [r["is_anomaly"] for r in with_shadow] == [r["is_anomaly"] for r in without]
    assert [r["severity_score"] for r in with_shadow] == [r["severity_score"] for r in without]
    assert all(r["shadow_ecod_score"] is not None for r in with_shadow)
    assert all(r["shadow_ecod_score"] is None for r in without)
    assert any(r["shadow_ecod_anomaly"] for r in with_shadow)


def test_orchestrator_without_shadow_attribute_still_runs():
    """The bench and some tests build orchestrators via __new__ (no constructor state)."""
    from lsadra.detection.detection_orchestrator import DetectionOrchestrator
    from lsadra.models.autoencoder_model import AutoencoderModel
    from lsadra.models.ensemble_model import EnsembleModel
    from lsadra.models.statistical_baseline import StatisticalBaselineModel

    orch = DetectionOrchestrator.__new__(DetectionOrchestrator)
    orch.baseline, orch.ensemble, orch.autoencoder = (
        StatisticalBaselineModel(),
        EnsembleModel(),
        AutoencoderModel(),
    )
    orch._trained = False
    out = orch._run_layers(_benign_df(repeat=1))
    assert out and out[0]["shadow_ecod_score"] is None
