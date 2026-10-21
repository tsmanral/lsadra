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
    # One device at 50 ev/s sends every 2 s: no wait for a fresh credential cache.
    assert step["auth_fresh_wait_s"] == 0


def test_fresh_auth_wait_only_for_devices_sending_less_often_than_half_the_ttl():
    bench = _load_harness()
    assert bench.AUTH_CACHE_TTL_S == 60  # the server default the ladder is tuned for
    # 100-event batches: interval = devices * 100 / rate.
    assert not bench.needs_fresh_auth(1, 25)    # every 4 s
    assert not bench.needs_fresh_auth(10, 50)   # every 20 s
    assert bench.needs_fresh_auth(10, 25)       # every 40 s
    assert bench.needs_fresh_auth(20, 50)       # every 40 s
    assert not bench.needs_fresh_auth(20, 100)  # every 20 s


def test_rewarm_after_the_wait_keeps_a_sparse_device_off_inline_bcrypt():
    """
    The case behind the slow first 25 ev/s step: a re-warm read on an entry
    younger than half its TTL queues no re-verify, so a device whose next batch
    comes 40 s later finds it expired. Re-warming once the entry is past half
    its TTL renews it instead.
    """
    from lsadra.ingestion.credential_cache import VerifiedCredentialCache

    bench = _load_harness()
    ttl = bench.AUTH_CACHE_TTL_S

    def next_batch_hits(wait_before_rewarm: float) -> bool:
        now = [0.0]
        cache = VerifiedCredentialCache(ttl, 10, clock=lambda: now[0])
        cache.remember("dev", "key", "$2b$hash")
        now[0] += 20.0                             # entry age when the settle ends
        now[0] += wait_before_rewarm
        assert cache.is_verified("dev", "key", "$2b$hash")
        if cache.claim_refresh("dev", "key", "$2b$hash"):
            cache.finish_refresh("dev", "key", "$2b$hash", ok=True)
        now[0] += 3.0 + 40.0                       # second settle, then 40 s between batches
        return cache.is_verified("dev", "key", "$2b$hash")

    assert not next_batch_hits(0.0)  # before: inline bcrypt on that batch
    assert next_batch_hits(ttl * bench.AUTH_REFRESH_AFTER_FRACTION + 1.0)


def test_trace_summary_names_what_a_slow_request_waited_on():
    import seed_demo

    bench = _load_harness()
    result = seed_demo.RateResult(
        offered_rate=100, devices=1, batch_size=100, scheduled_batches=2, nominal_duration_s=2
    )
    result.records = [
        seed_demo.RequestRecord(0.0, 0.300, 200, 100, 100, request_id="r-0"),
        seed_demo.RequestRecord(1.0, 0.020, 200, 100, 100, request_id="r-1"),
    ]
    records = [
        {"kind": "request", "id": "r-0", "t0": 10.0, "t1": 10.290,
         "calls": [["get_device", 10.001, 10.002, "t"], ["store", 10.010, 10.020, "t"]]},
        {"kind": "request", "id": "r-1", "t0": 11.0, "t1": 11.015,
         "calls": [["store", 11.002, 11.012, "t"]]},
        {"kind": "gc", "gen": 2, "t0": 10.030, "t1": 10.280},
        {"kind": "detection", "t0": 9.0, "t1": 10.5},
    ]
    summary = bench.summarize_trace(result, records)
    assert summary["requests_traced"] == 2
    assert summary["slow_requests"] == 1
    assert summary["slow_causes"] == {"gc": 1}
    slowest = summary["slowest"][0]
    assert slowest["id"] == "r-0" and slowest["cause"] == "gc"
    assert slowest["gc_gen2_ms"] == 250.0
    assert slowest["detection_overlap_ms"] == 290.0
    assert summary["gc"] == {"collections": 1, "gen2": 1, "max_ms": 250.0, "total_ms": 250.0}
