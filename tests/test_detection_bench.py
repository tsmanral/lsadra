"""
Tests for the detection bench (benchmarks/detection/).

Checks the metric maths, the Windows event adapters (on synthetic events, never
real log lines) and one tiny end-to-end run of the harness. Nothing here asserts
detection quality: the committed results file is the record of that.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_DIR = REPO_ROOT / "benchmarks" / "detection"
sys.path.insert(0, str(BENCH_DIR))

import bench_events  # noqa: E402
import bench_metrics as metrics  # noqa: E402


def _rec(role, score, technique=None, instance=None):
    return {
        "role": role,
        "technique": technique,
        "instance": instance,
        "s": score,
        "is_anomaly": score > 0.5,
        "mitre_technique": technique,
        "scored": True,
    }


class TestMetrics:
    def test_threshold_allows_floor_of_fpr_negatives(self):
        neg = [float(i) for i in range(1000)]
        t = metrics.threshold_for_fpr(neg, 0.01)
        assert sum(1 for s in neg if s > t) == 10
        t = metrics.threshold_for_fpr(neg, 0.001)
        assert sum(1 for s in neg if s > t) == 1

    def test_tied_scores_never_exceed_target(self):
        neg = [1.0] * 990 + [0.0] * 10  # a saturated score
        recs = [_rec("negative", s) for s in neg] + [_rec("positive", 1.0, "T1110.001", "a")]
        out = metrics.score_at_fpr(recs, "s", 0.01)
        assert out["achieved_fpr"] <= 0.01
        assert out["event_tpr"] == 0.0  # tied with benign, so not separable
        assert out["negatives_at_threshold"] == 990

    def test_per_technique_and_instance_rates(self):
        recs = [_rec("negative", i / 1000) for i in range(1000)]
        recs += [
            _rec("positive", 2.0, "T1110.001", "i1"),
            _rec("positive", 0.0, "T1110.001", "i1"),
            _rec("positive", 0.0, "T1053.005", "i2"),
            _rec("context", 5.0),
        ]
        out = metrics.score_at_fpr(recs, "s", 0.01)
        assert out["techniques"]["T1110.001"]["event_tpr"] == 0.5
        assert out["techniques"]["T1110.001"]["instance_tpr"] == 1.0
        assert out["techniques"]["T1053.005"]["event_tpr"] == 0.0
        assert out["event_tpr"] == round(1 / 3, 4)  # context events count for nothing

    def test_verdict_alerts_per_host_day(self):
        recs = [_rec("negative", 1.0)] * 30 + [_rec("negative", 0.0)] * 70
        out = metrics.verdict_metrics(recs, host_days=10)
        assert out["fpr"] == 0.3
        assert out["alerts_per_host_day_benign"] == 3.0


_XML = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID>"
    "<TimeCreated SystemTime='2026-01-15T02:00:01.1234567Z'/><Channel>Security</Channel>"
    "<Computer>demo-host-01</Computer></System><EventData>"
    "<Data Name='TargetUserName'>alice.demo</Data><Data Name='IpAddress'>198.51.100.37</Data>"
    "</EventData></Event>"
)

_SPLUNK = """01/15/2026 02:00:05 AM
LogName=Security
SourceName=Microsoft Windows security auditing.
EventCode=4771
ComputerName=demo-host-01
Message=Kerberos pre-authentication failed.

Account Information:
	Security ID:		DEMO\\bob.demo
	Account Name:		bob.demo

Additional Information:
	Failure Code:		0x18
01/15/2026 02:00:06 AM
LogName=System
SourceName=Service Control Manager
EventCode=7045
ComputerName=demo-host-01
Message=A service was installed in the system.
"""


class TestWindowsAdapters:
    def test_xml_failed_logon(self):
        (ev,) = list(bench_events.iter_windows_xml_lines(_XML))
        assert ev.event_type == "auth_failure"
        assert ev.effective_username == "alice.demo"
        assert ev.source_ip == "198.51.100.37"
        assert ev.timestamp.year == 2026

    def test_splunk_text_kerberos_and_service(self):
        evs = list(bench_events.iter_splunk_wineventlog(_SPLUNK))
        assert [e.event_type for e in evs] == ["auth_failure", "service_install"]
        assert evs[0].effective_username == "bob.demo"

    def test_dataset_labels_positive_and_context(self, tmp_path):
        p = tmp_path / "x.log"
        p.write_text(_SPLUNK, encoding="utf-8")
        entry = {
            "id": "t/x",
            "source": "test",
            "format": "splunk_wineventlog",
            "technique": "T1543.003",
            "positive_event_types": ["service_install"],
        }
        evs = bench_events.load_windows_dataset(entry, p)
        assert [e.role for e in evs] == ["context", "positive"]
        assert evs[1].instance == "t/x"


def test_synthetic_benign_is_seeded_and_hygienic():
    a = bench_events.generate_benign(hosts=3, days=2, seed=1)
    b = bench_events.generate_benign(hosts=3, days=2, seed=1)
    assert [(e.timestamp, e.event_type) for e in a] == [(e.timestamp, e.event_type) for e in b]
    for e in a:
        assert e.role == "negative"
        if e.effective_username not in (None, "root", "SYSTEM"):
            assert e.effective_username.endswith(".demo")
        if e.source_ip:
            assert e.source_ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_manifest_never_points_inside_the_repo():
    manifest = json.loads((BENCH_DIR / "datasets.json").read_text(encoding="utf-8"))
    assert manifest["sources"]["evtx_attack_samples"]["test_only"] is True
    for entry in manifest["datasets"]:
        assert len(entry["sha256"]) == 64
        assert entry["source"] in manifest["sources"]
        assert entry["positive_event_types"]


def test_end_to_end_tiny_run(tmp_path):
    import run_detection_bench

    out = tmp_path / "bench.json"
    rc = run_detection_bench.main(
        [
            "--hosts",
            "2",
            "--days",
            "2",
            "--train-days",
            "1",
            "--datasets",
            "demo",
            "--configs",
            "production",
            "retrained-full",
            "--workers",
            "1",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["schema"] == "lsadra-detection-bench/1"
    assert set(report["results"]) == {"production", "retrained-full"}
    for res in report["results"].values():
        assert res["events"]["positive"] > 0 and res["events"]["negative"] > 0
        assert set(res["scores"]) == {
            "severity_score",
            "layer1_z",
            "layer2_ensemble",
            "layer3_autoencoder",
            "shadow_ecod",
        }
        for by_fpr in res["scores"].values():
            assert set(by_fpr) == {"0.01", "0.001"}
            for v in by_fpr.values():
                assert v["achieved_fpr"] <= v["target_fpr"]
    training = report["results"]["production"]["training"]
    assert {a["status"] for a in training["attempts"]} <= {"promoted", "rejected", "failed"}
    assert "training" not in report["results"]["retrained-full"]
    assert out.with_suffix(".md").exists()


class TestChallengers:
    def test_ecod_ranks_tail_values_highest(self):
        import numpy as np

        import challengers

        rng = np.random.default_rng(0)
        X = rng.normal(size=(500, 3))
        ecod = challengers.ECOD().fit(X)
        s = ecod.score(np.array([[0.0, 0.0, 0.0], [6.0, 0.0, 0.0], [0.0, -6.0, 0.0]]))
        assert s[1] > s[0] and s[2] > s[0]

    def test_feature_matrix_is_fixed_width(self):
        import challengers

        rows = [
            {
                "id": 1,
                "timestamp": "2026-01-15T02:00:01.000000+00:00",
                "device_id": "d",
                "user_id": "u",
                "host": "h",
                "effective_username": "alice.demo",
                "source_ip": "198.51.100.37",
                "event_type": "auth_failure",
                "raw_message": "",
            }
        ]
        from lsadra.features.feature_extractor import build_features

        X = challengers.feature_matrix(build_features(rows))
        assert X.shape == (1, len(challengers.feature_names()))
        assert X[0, challengers.feature_names().index("et_auth_failure")] == 1.0

    def test_iforest_onnx_matches_sklearn(self):
        pytest.importorskip("onnxruntime")
        pytest.importorskip("skl2onnx")
        import numpy as np

        import challengers

        X = np.random.default_rng(1).normal(size=(300, 5)).astype(np.float32)
        _, info = challengers._iforest_onnx(X, seed=1)
        assert info["max_abs_diff_vs_sklearn"] < 1e-4

    def test_tiny_run_with_challengers(self, tmp_path):
        for mod in ("onnxruntime", "skl2onnx", "lightgbm"):
            pytest.importorskip(mod)
        import run_detection_bench

        out = tmp_path / "bench.json"
        rc = run_detection_bench.main(
            [
                "--hosts",
                "2",
                "--days",
                "2",
                "--train-days",
                "1",
                "--datasets",
                "demo",
                "--configs",
                "retrained-full",
                "--workers",
                "1",
                "--challengers",
                "--cache-dir",
                str(tmp_path / "cache"),
                "--output",
                str(out),
            ]
        )
        assert rc == 0
        res = json.loads(out.read_text(encoding="utf-8"))["results"]["retrained-full"]
        for key in ("ch_iforest", "ch_ecod", "ch_unsup", "ch_lgbm"):
            assert res["scores"][key]["0.01"]["achieved_fpr"] <= 0.01
        assert res["challengers"]["iforest"]["max_abs_diff_vs_sklearn"] < 1e-4


def test_product_ecod_matches_the_bench_challenger():
    import numpy as np

    import challengers
    from lsadra.models.ecod_model import ECODModel

    rng = np.random.default_rng(3)
    X = np.round(rng.normal(size=(600, len(challengers.feature_names()))), 2)
    probe = np.round(rng.normal(scale=2.0, size=(50, X.shape[1])), 2)
    np.testing.assert_allclose(
        ECODModel().fit(X).score(probe), challengers.ECOD().fit(X).score(probe)
    )
