"""
Smoke test for the M1 ingest benchmark harness (benchmarks/run_ingest_bench.py).

Runs the real harness end to end — real core in a subprocess on a temp DB, real
onboarding and /api/events/batch — for 5 s at 50 events/s with detection off,
and checks the result file carries the committed baseline schema. It asserts
shape and basic sanity, never performance: CI machines vary too much.
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_prod_mode(code: str, **extra_env: str) -> subprocess.CompletedProcess:
    """Run *code* in a fresh interpreter with dev mode OFF (production config)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("LSADRA_")}
    env.update(
        LSADRA_DEV_MODE="false",
        LSADRA_JWT_SECRET="x" * 48,
        LSADRA_REQUIRE_TLS="false",
        **extra_env,
    )
    return subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=120,
    )


def test_detection_skip_flag_refuses_to_boot_outside_dev_mode():
    proc = _run_prod_mode("import lsadra.config", LSADRA_BENCH_SKIP_DETECTION="true")
    assert proc.returncode != 0
    assert "requires LSADRA_DEV_MODE=true" in proc.stderr


def test_health_exposes_no_benchmark_telemetry_outside_dev_mode():
    code = (
        "import asyncio, json, server\n"
        "print(json.dumps(asyncio.run(server.api_health())))\n"
    )
    proc = _run_prod_mode(code)
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout.strip().splitlines()[-1])
    assert body["status"] == "ok"
    assert "benchmark" not in body


def _load_harness():
    spec = importlib.util.spec_from_file_location(
        "run_ingest_bench", REPO_ROOT / "benchmarks" / "run_ingest_bench.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_harness_emits_schema_at_50_events_per_second(tmp_path):
    bench = _load_harness()
    out = tmp_path / "bench.json"
    code = bench.main(
        ["--detection", "off", "--devices", "1", "--rates", "50", "--duration", "5",
         "--min-requests", "1", "--repeats", "1", "--output", str(out)]
    )
    assert code == 0

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["schema"] == "lsadra.ingest-bench/1"
    for key in ("cpu", "ram_gb", "os", "python"):
        assert report["machine"][key]
    assert report["params"]["step_duration_s"] == 5
    # Payload set is pinned so the baseline does not drift as the corpus grows.
    assert sorted(report["params"]["scenarios"]) == [
        "benign_background", "data_movement_offhours",
        "persistence_new_service", "ssh_bruteforce",
    ]

    (run,) = report["runs"]
    assert run["detection"] == "off"
    assert set(run["loop_lag_idle_ms"]) >= {"p50", "p99", "samples"}
    (config,) = run["configs"]
    assert config["devices"] == 1
    (step,) = config["steps"]

    assert step["offered_ev_s"] == 50
    assert step["requests_ok"] == step["requests_scheduled"] > 0
    assert step["requests_429"] == step["requests_error"] == 0
    assert step["events_accepted"] == step["requests_ok"] * 100
    assert step["sustained_ev_s"] > 0
    for q in ("p50", "p95", "p99"):
        assert step["latency_ms"][q] > 0
    assert step["loop_lag_ms"]["samples"] > 0
    assert step["loop_lag_ms"]["p99"] is not None
    assert step["rss_mb"]["max"] > 0
    assert isinstance(step["degraded"], list)
