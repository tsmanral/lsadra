"""
G-17 — model files are verified before they are deserialized.

Regression tests: each one fails on the old loaders, which unpickled whatever
file sat in the models folder (and loaded torch state with weights_only=False). The autoencoder is now
plain JSON, so its tests check that nothing is ever unpickled for it.
A tampered, unlisted or re-signed file must never be deserialized; the stack
falls back to fresh, untrained models instead.
"""

import io
import json
import os

import pytest

from tests.fixtures import make_feature_matrix


class _Boom:
    """Unpickling this object runs code: it creates the marker file."""

    def __init__(self, marker: str):
        self.marker = marker

    def __reduce__(self):
        return (open, (self.marker, "w"))


@pytest.fixture
def model_dir(tmp_path):
    d = tmp_path / "models"
    d.mkdir()
    return d


def _write_malicious_pickle(path, marker):
    import joblib

    joblib.dump(_Boom(str(marker)), str(path))


def test_ensemble_load_refuses_unlisted_pickle(model_dir, tmp_path):
    from lsadra.models.ensemble_model import EnsembleModel

    marker = tmp_path / "pwned"
    target = model_dir / "ensemble.joblib"
    _write_malicious_pickle(target, marker)

    model = EnsembleModel.load(target)

    assert not marker.exists(), "an unverified model file was deserialized"
    assert isinstance(model, EnsembleModel)
    assert not model.models[0].is_fitted


def test_manifest_with_forged_hmac_is_rejected(model_dir, tmp_path):
    """Someone who can write the folder can recompute the SHA-256, not the HMAC."""
    from lsadra.models.ensemble_model import EnsembleModel
    from lsadra.models.integrity import sha256_file

    marker = tmp_path / "pwned"
    target = model_dir / "ensemble.joblib"
    _write_malicious_pickle(target, marker)
    files = {
        "ensemble.joblib": {
            "sha256": sha256_file(target),
            "size": target.stat().st_size,
            "written_at": "2026-01-01T00:00:00+00:00",
        }
    }
    (model_dir / "manifest.json").write_text(
        json.dumps({"version": 1, "files": files, "hmac": "0" * 64})
    )

    EnsembleModel.load(target)
    assert not marker.exists()


def test_manifest_signed_with_another_key_is_rejected(model_dir, tmp_path, monkeypatch):
    from lsadra.models.ensemble_model import EnsembleModel
    from lsadra.models.integrity import ModelStore

    marker = tmp_path / "pwned"
    buf = io.BytesIO()
    import joblib

    joblib.dump(_Boom(str(marker)), buf)
    monkeypatch.setenv("LSADRA_MODEL_SIGNING_KEY", "attacker-key")
    ModelStore(model_dir).write_bytes("ensemble.joblib", buf.getvalue())
    monkeypatch.setenv("LSADRA_MODEL_SIGNING_KEY", "operator-key")

    EnsembleModel.load(model_dir / "ensemble.joblib")
    assert not marker.exists()


def test_modified_file_after_signing_is_rejected(model_dir, tmp_path):
    from lsadra.models.ensemble_model import EnsembleModel
    from lsadra.models.integrity import ModelStore

    ens = EnsembleModel()
    ens.train(make_feature_matrix(n_rows=60))
    ens.save(model_dir / "ensemble.joblib")
    assert ModelStore(model_dir).sha256("ensemble.joblib")

    marker = tmp_path / "pwned"
    _write_malicious_pickle(model_dir / "ensemble.joblib", marker)

    loaded = EnsembleModel.load(model_dir / "ensemble.joblib")
    assert not marker.exists()
    assert not loaded.models[0].is_fitted


def test_base_model_load_raises_on_unverified_file(model_dir, tmp_path):
    from lsadra.models.integrity import ModelIntegrityError
    from lsadra.models.isolation_forest import IsolationForestModel

    marker = tmp_path / "pwned"
    target = model_dir / "Isolation_Forest.joblib"
    _write_malicious_pickle(target, marker)

    with pytest.raises(ModelIntegrityError):
        IsolationForestModel.load(target)
    assert not marker.exists()


def test_autoencoder_state_is_json_never_unpickled(model_dir, tmp_path):
    """A verified autoencoder file is parsed as JSON; pickle bytes are refused."""
    from lsadra.models.autoencoder_model import AutoencoderModel
    from lsadra.models.integrity import ModelStore

    marker = tmp_path / "pwned"
    import pickle

    ModelStore(model_dir).write_bytes(
        "autoencoder.json", pickle.dumps({"payload": _Boom(str(marker))})
    )

    ae = AutoencoderModel()
    assert ae.load(model_dir / "autoencoder.json") is False
    assert not marker.exists()
    assert not ae.is_fitted


def test_autoencoder_refuses_signed_but_malformed_state(model_dir):
    """Signed JSON whose shapes do not form a valid network is not loaded."""
    from lsadra.models.autoencoder_model import STATE_FORMAT, AutoencoderModel
    from lsadra.models.integrity import ModelStore

    ae = AutoencoderModel()
    n = len(ae.features)
    good = {
        "format": STATE_FORMAT,
        "features": ae.features,
        "weights": [[[0.0] * 3] * n, [[0.0] * n] * 3],
        "biases": [[0.0] * 3, [0.0] * n],
        "mean": [0.0] * n,
        "std": [1.0] * n,
        "threshold": 1.0,
    }
    store = ModelStore(model_dir)
    store.save_json("autoencoder.json", good)
    assert AutoencoderModel().load(model_dir / "autoencoder.json") is True

    bad_states = [
        {**good, "format": "something-else"},
        {**good, "features": ["x"] * n},
        {**good, "weights": [[[0.0] * 3] * n, [[0.0] * 2] * 3]},  # does not chain
        {**good, "weights": [[[0.0] * 3] * n, [[0.0] * (n - 1)] * 3],
         "biases": [[0.0] * 3, [0.0] * (n - 1)]},  # wrong output size
        {**good, "std": [0.0] * n},
        {**good, "threshold": float("nan")},
        {**good, "mean": "not a list"},
        ["not", "a", "dict"],
    ]
    for state in bad_states:
        store.save_json("autoencoder.json", state)
        ae2 = AutoencoderModel()
        assert ae2.load(model_dir / "autoencoder.json") is False, state
        assert not ae2.is_fitted


def test_autoencoder_refuses_unlisted_file(model_dir):
    from lsadra.models.autoencoder_model import AutoencoderModel

    (model_dir / "autoencoder.json").write_text("{}")

    assert AutoencoderModel().load(model_dir / "autoencoder.json") is False


def test_legacy_torch_autoencoder_file_is_ignored_and_triggers_retrain(model_dir, tmp_path):
    """An upgraded install's old autoencoder.pt is never opened; models retrain."""
    from tests.fixtures import setup_test_db

    setup_test_db(tmp_path)
    from lsadra.detection.detection_orchestrator import DetectionOrchestrator
    from lsadra.models.ensemble_model import EnsembleModel
    from lsadra.models.integrity import ModelStore

    marker = tmp_path / "pwned"
    import pickle

    ModelStore(model_dir).write_bytes("autoencoder.pt", pickle.dumps(_Boom(str(marker))))
    ens = EnsembleModel()
    ens.train(make_feature_matrix(n_rows=80))
    ens.save(model_dir / "ensemble.joblib")

    orch = DetectionOrchestrator(model_dir=model_dir)
    assert not marker.exists()
    assert not orch.autoencoder.is_fitted
    assert orch._trained is False


def test_orchestrator_cold_start_ignores_tampered_models(model_dir, tmp_path):
    from tests.fixtures import setup_test_db

    setup_test_db(tmp_path)
    from lsadra.detection.detection_orchestrator import DetectionOrchestrator

    marker = tmp_path / "pwned"
    _write_malicious_pickle(model_dir / "ensemble.joblib", marker)

    orch = DetectionOrchestrator(model_dir=model_dir)
    assert not marker.exists()
    assert orch._trained is False


def test_signed_round_trip_still_loads(model_dir):
    from lsadra.models.autoencoder_model import AutoencoderModel
    from lsadra.models.ensemble_model import EnsembleModel

    df = make_feature_matrix(n_rows=80)
    ens = EnsembleModel()
    ens.train(df)
    ens.save(model_dir / "ensemble.joblib")
    ae = AutoencoderModel(epochs=2)
    ae.train(df)
    ae.save(model_dir / "autoencoder.json")

    loaded = EnsembleModel.load(model_dir / "ensemble.joblib")
    assert loaded.models[0].is_fitted
    assert len(loaded.predict(df)) == len(df)
    ae2 = AutoencoderModel()
    assert ae2.load(model_dir / "autoencoder.json") is True
    assert [r["is_ae_anomaly"] for r in ae2.score(df)] == [
        r["is_ae_anomaly"] for r in ae.score(df)
    ]


def test_store_rejects_path_names(model_dir):
    from lsadra.models.integrity import ModelStore

    store = ModelStore(model_dir)
    for bad in ("../x.joblib", "sub/x.joblib", "manifest.json", ".hidden", ""):
        with pytest.raises(ValueError):
            store.write_bytes(bad, b"x")


def test_symlinked_model_file_is_refused(model_dir, tmp_path):
    from lsadra.models.integrity import ModelIntegrityError, ModelStore

    store = ModelStore(model_dir)
    store.write_bytes("baseline.json", b"{}")
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_bytes(b"{}")
    os.unlink(model_dir / "baseline.json")
    try:
        os.symlink(elsewhere, model_dir / "baseline.json")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ModelIntegrityError):
        store.read_verified("baseline.json")


def test_pinned_download_hash(tmp_path):
    from lsadra.models.integrity import ModelIntegrityError, sha256_file, verify_pinned_file

    weights = tmp_path / "model.gguf"
    weights.write_bytes(b"weights")
    good = sha256_file(weights)
    assert verify_pinned_file(weights, good) == weights
    with pytest.raises(ModelIntegrityError):
        verify_pinned_file(weights, "0" * 64)
    with pytest.raises(ModelIntegrityError):
        verify_pinned_file(weights, "")
