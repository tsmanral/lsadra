#!/usr/bin/env python3
"""
Detection bench: scores LSADRA's current detection pipeline against labelled data.

It builds one event stream per bench host (seeded synthetic background, with the
demo corpus scenarios and the pinned public attack captures injected into the
test period), replays it through the unmodified pipeline
(``build_features`` + ``DetectionOrchestrator._run_layers``) and records, per
MITRE ATT&CK technique, the true-positive rate at 1 % and 0.1 % false-positive
rate, plus alerts per host per day.

Three configurations are scored:

``production``
    What a fresh install does today. Detection runs per device on the events
    that arrived since its last run (agent flush 3 s / 50 events, per-device
    throttle 5 s, at most 500 events per run), so features only see that chunk.
    The first device to pass the baselining threshold trains every model, once,
    on its first <= 500 events.
``retrained-online``
    Same online chunking, but every layer is trained on all hosts' training
    days first: today's algorithms with clean training data.
``retrained-full``
    Every layer trained on the training days, and features computed over each
    device's whole stream instead of per chunk: a ceiling for today's
    algorithms and features.

    python benchmarks/detection/fetch_datasets.py    # optional public subsets
    python benchmarks/detection/run_detection_bench.py --output results/run.json
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import platform
import random
import subprocess
import sys
import time
import warnings
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO_ROOT))

# Same as tests/conftest.py: keep production boot guards out of an offline run.
os.environ.setdefault("LSADRA_DEV_MODE", "true")
os.environ.setdefault("LSADRA_SCHEDULER_ENABLED", "false")

import bench_events  # noqa: E402
import fetch_datasets  # noqa: E402
import bench_metrics as metrics  # noqa: E402

logger = logging.getLogger("detection_bench")

CONFIGS = ("production", "retrained-online", "retrained-full")
SCORE_KEYS = ["severity_score", "layer1_z", "layer2_ensemble", "layer3_autoencoder"]
FPRS = [0.01, 0.001]

# Agent and server behaviour the online replay mirrors.
AGENT_FLUSH_SECONDS = 3.0      # lsadra/endpoint_agent/linux_agent.py flush_interval_seconds
AGENT_BATCH_SIZE = 50          # linux_agent.py batch_size
EVENTS_PER_RUN = 500           # get_events_since() default limit
BENCH_USER_ID = "bench-owner"  # the dashboard account that owns every device


# ============================================================================
# Stream assembly
# ============================================================================

def _git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
    except Exception:
        return "unknown"


def _inject(instance: List[bench_events.BenchEvent], host: str, day: int) -> List[bench_events.BenchEvent]:
    """Move an attack instance onto *host*, starting on bench *day* at its
    original UTC time of day, keeping relative spacing."""
    if not instance:
        return []
    first = min(e.timestamp for e in instance)
    tod = first - first.replace(hour=0, minute=0, second=0, microsecond=0)
    start = bench_events.BASE_DATE + timedelta(days=day) + tod
    for e in instance:
        e.timestamp = start + (e.timestamp - first)
        e.host = host
    return instance


def build_stream(args: argparse.Namespace) -> Tuple[List[bench_events.BenchEvent], Dict[str, Any]]:
    stream = bench_events.generate_benign(args.hosts, args.days, args.seed)
    hosts = [f"bench-host-{h + 1:02d}" for h in range(args.hosts)]
    linux = [h for i, h in enumerate(hosts) if i % 5 < 3]
    windows = [h for i, h in enumerate(hosts) if i % 5 >= 3] or linux
    test_days = list(range(args.train_days, args.days))
    rng = random.Random(args.seed + 1)
    injected: List[Dict[str, Any]] = []
    slot = 0

    def place(name: str, evs: List[bench_events.BenchEvent], pool: List[str]) -> None:
        nonlocal slot
        host = pool[slot % len(pool)]
        day = test_days[(slot * 3 + rng.randint(0, 1)) % len(test_days)]
        slot += 1
        stream.extend(_inject(evs, host, day))
        injected.append({"instance": name, "host": host, "day": day, "events": len(evs)})

    if "demo" in args.datasets:
        for scenario, evs in bench_events.load_demo_corpus().items():
            pool = windows if scenario == "persistence_new_service" else linux
            place(f"demo/{scenario}", evs, pool)

    manifest = fetch_datasets.load_manifest()
    skipped: List[str] = []
    for entry in manifest["datasets"]:
        src = entry["source"]
        wanted = ("splunk" in args.datasets and src == "splunk_attack_data") or (
            "evtx" in args.datasets and src == "evtx_attack_samples")
        if not wanted:
            continue
        if not fetch_datasets.is_cached(args.cache_dir, entry):
            skipped.append(entry["id"])
            continue
        evs = bench_events.load_windows_dataset(entry, fetch_datasets.cache_path(args.cache_dir, entry))
        place(entry["id"], evs, windows)
    if skipped:
        logger.warning("Not cached, skipped (run fetch_datasets.py): %s", ", ".join(skipped))

    stream.sort(key=lambda e: (e.timestamp, e.host))
    info = {
        "hosts": args.hosts,
        "linux_hosts": len(linux),
        "windows_hosts": len([h for i, h in enumerate(hosts) if i % 5 >= 3]),
        "days": args.days,
        "train_days": args.train_days,
        "test_days": len(test_days),
        "injected": injected,
        "skipped_not_cached": skipped,
    }
    return stream, info


def to_rows(stream: List[bench_events.BenchEvent]) -> List[Dict[str, Any]]:
    """Rows as ``normalized_events`` stores them (ids in arrival order)."""
    rows = []
    for i, ev in enumerate(stream, start=1):
        f = ev.contract_fields()
        rows.append({
            "id": i,
            "timestamp": f["timestamp"],
            "device_id": ev.host,
            "user_id": BENCH_USER_ID,
            "host": f["host"],
            "effective_username": f["effective_username"],
            "source_ip": f["source_ip"],
            "event_type": f["event_type"],
            "raw_message": f["raw_message"],
            "attributes": json.dumps(f["attributes"]),
            "is_synthetic": 0,
            "_ts": ev.timestamp.timestamp(),
        })
    return rows


# ============================================================================
# Replay through the real pipeline
# ============================================================================

def _quiet_ml_logs() -> None:
    for name in ("lsadra", "shap", "numba"):
        logging.getLogger(name).setLevel(logging.WARNING)
    warnings.filterwarnings("ignore")


def _new_orchestrator(seed: int):
    """A DetectionOrchestrator with fresh layers and no persistence side effects.

    ``__init__`` would load models from ``data/models`` and open the profile
    store; the bench wants neither, so it sets the same attributes directly and
    calls the real ``_run_layers``.
    """
    import numpy as np

    from lsadra.detection.detection_orchestrator import DetectionOrchestrator
    from lsadra.models.autoencoder_model import AutoencoderModel
    from lsadra.models.ensemble_model import EnsembleModel
    from lsadra.models.statistical_baseline import StatisticalBaselineModel

    random.seed(seed)
    np.random.seed(seed)
    orch = DetectionOrchestrator.__new__(DetectionOrchestrator)
    orch.baseline = StatisticalBaselineModel()
    orch.ensemble = EnsembleModel()
    orch.autoencoder = AutoencoderModel()
    orch._trained = False
    orch._last_run = {}
    return orch


def _train(orch, df) -> bool:
    """``DetectionOrchestrator.train`` without ``_save_models`` (no disk, no DB).

    Same order and the same failure behaviour: a layer that raises leaves the
    earlier layers trained and ``_trained`` False.
    """
    try:
        orch.baseline.train(df)
        orch.ensemble.train(df)
        orch.autoencoder.train(df)
    except Exception as exc:
        logger.info("training failed (%s): %s", type(exc).__name__, exc)
        return False
    orch._trained = True
    return True


def _clean(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]


def online_runs(rows: List[Dict[str, Any]], throttle: float) -> List[Tuple[str, List[Dict[str, Any]], bool]]:
    """Detection runs as the online path would execute them.

    Returns ``(device_id, chunk, final_flush)`` in execution order. Each device's
    agent ships a batch every 3 s or 50 events; a batch arrival triggers a run
    if the device's last run was at least ``throttle`` seconds ago, and the run
    takes up to 500 stored-but-unprocessed events. Events still pending when
    the stream ends are processed in a final flush (live, they would wait for
    the device's next batch).
    """
    by_dev: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_dev[r["device_id"]].append(r)
    batches: List[Tuple[float, int, str, List[Dict[str, Any]]]] = []
    for dev, drows in by_dev.items():
        cur: List[Dict[str, Any]] = []
        for r in drows:
            if cur and (r["_ts"] - cur[0]["_ts"] > AGENT_FLUSH_SECONDS or len(cur) >= AGENT_BATCH_SIZE):
                batches.append((cur[-1]["_ts"], cur[0]["id"], dev, cur))
                cur = []
            cur.append(r)
        if cur:
            batches.append((cur[-1]["_ts"], cur[0]["id"], dev, cur))
    batches.sort(key=lambda b: (b[0], b[1]))

    pending: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    last_run: Dict[str, float] = defaultdict(lambda: -math.inf)
    runs: List[Tuple[str, List[Dict[str, Any]], bool]] = []
    for arrival, _, dev, batch in batches:
        pending[dev].extend(batch)
        if arrival - last_run[dev] >= throttle:
            last_run[dev] = arrival
            runs.append((dev, pending[dev][:EVENTS_PER_RUN], False))
            pending[dev] = pending[dev][EVENTS_PER_RUN:]
    for dev, rest in pending.items():
        for i in range(0, len(rest), EVENTS_PER_RUN):
            runs.append((dev, rest[i:i + EVENTS_PER_RUN], True))
    return runs


def _features(chunk: List[Dict[str, Any]]):
    from lsadra.features.feature_extractor import build_features

    return build_features(_clean(chunk))


def online_features(rows: List[Dict[str, Any]], workers: int):
    """Detection runs plus each run's feature frame (computed once, shared by configs)."""
    from lsadra.config import DETECTION_THROTTLE_SECONDS

    runs = online_runs(rows, DETECTION_THROTTLE_SECONDS)
    chunks = [chunk for _, chunk, _ in runs]
    if workers > 1:
        import multiprocessing as mp

        with mp.get_context("spawn").Pool(workers, initializer=_quiet_ml_logs) as pool:
            feats = pool.map(_features, chunks, chunksize=64)
    else:
        feats = [_features(c) for c in chunks]
    return runs, feats


def run_config(config: str, rows: List[Dict[str, Any]], test_start: float, seed: int,
               online: Optional[Tuple[List[Any], List[Any]]] = None) -> Dict[int, Dict[str, Any]]:
    """Score every test-period row under *config*; returns results by event id."""
    import pandas as pd

    from lsadra.config import MIN_BASELINE_EVENTS

    orch = _new_orchestrator(seed)
    results: Dict[int, Dict[str, Any]] = {}
    ts_by_id = {r["id"]: r["_ts"] for r in rows}

    def score(df) -> None:
        for res in orch._run_layers(df.reset_index(drop=True)):
            results[res["event_id"]] = res

    if config == "retrained-full":
        by_dev: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for r in rows:
            by_dev[r["device_id"]].append(r)
        feats = pd.concat([_features(drows) for drows in by_dev.values()], ignore_index=True)
        is_test = feats["id"].map(ts_by_id) >= test_start
        if not _train(orch, feats[~is_test].reset_index(drop=True)):
            raise RuntimeError("retrained-full: training failed")
        score(feats[is_test])
        return results

    assert online is not None
    runs, chunk_feats = online
    if config == "retrained-online":
        train = pd.concat([f[f["id"].map(ts_by_id) < test_start] for f in chunk_feats if not f.empty],
                          ignore_index=True)
        if not _train(orch, train):
            raise RuntimeError("retrained-online: training failed")

    totals: Dict[str, int] = defaultdict(int)
    stored: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    deferred: List[Any] = []
    for (dev, chunk, _final), df in zip(runs, chunk_feats):
        stored[dev].extend(chunk)
        totals[dev] += len(chunk)
        if totals[dev] < MIN_BASELINE_EVENTS:
            continue  # BASELINING: events stored, no detection
        if config == "production" and not orch._trained:
            # _auto_train: all stored events for this device, first 500.
            first = sorted(stored[dev], key=lambda r: r["id"])[:EVENTS_PER_RUN]
            _train(orch, _features(first))
        if chunk[-1]["_ts"] < test_start or df.empty:
            continue  # training period: nothing is measured (scoring has no side effects)
        if orch._trained:
            deferred.append(df)  # model state is final from here on
        else:
            score(df)
    if deferred:
        score(pd.concat(deferred, ignore_index=True))
    return results


def to_records(stream: List[bench_events.BenchEvent], rows: List[Dict[str, Any]],
               results: Dict[int, Dict[str, Any]], test_start: float) -> List[Dict[str, Any]]:
    recs = []
    for ev, row in zip(stream, rows):
        if row["_ts"] < test_start:
            continue
        res = results.get(row["id"])
        scored = res is not None
        recs.append({
            "role": ev.role,
            "technique": ev.technique,
            "instance": ev.instance,
            "scored": scored,
            "severity_score": float(res["severity_score"]) if scored else metrics.NEG_INF,
            "layer1_z": float(res["layer1_score"]) if scored else metrics.NEG_INF,
            "layer2_ensemble": float(res["layer2_score"]) if scored else metrics.NEG_INF,
            "layer3_autoencoder": float(res["layer3_score"]) if scored else metrics.NEG_INF,
            "is_anomaly": bool(res["is_anomaly"]) if scored else False,
            "mitre_technique": res["mitre_technique"] if scored else None,
        })
    return recs


# ============================================================================
# Report
# ============================================================================

def _versions() -> Dict[str, str]:
    out = {"python": platform.python_version()}
    for mod in ("numpy", "pandas", "sklearn"):
        try:
            out[mod] = __import__(mod).__version__
        except Exception:
            out[mod] = "missing"
    return out


def render_markdown(report: Dict[str, Any]) -> str:
    m = report["meta"]
    lines = [
        f"# Detection bench: {m['label']}",
        "",
        f"Commit `{m['git_sha'][:7]}`, {m['generated_at'][:10]}. "
        f"{m['stream']['hosts']} hosts x {m['stream']['test_days']} test days "
        f"({m['stream']['train_days']} training days before them), seed {m['seed']}. "
        f"Datasets: {', '.join(m['datasets'])}.",
        "",
        "Generated by `benchmarks/detection/run_detection_bench.py`; the JSON next to this file has every number.",
        "",
    ]
    for cfg, res in report["results"].items():
        ev = res["events"]
        dv = res["deployed_verdict"]
        lines += [
            f"## {cfg}",
            "",
            f"{ev.get('negative', 0)} benign and {ev.get('positive', 0)} attack events in the test period "
            f"({ev.get('context', 0)} context events not counted; {res['unscored']} events never scored).",
            "",
            f"Deployed verdict (`is_anomaly`): FPR {dv['fpr']}, event TPR {dv['event_tpr']}, "
            f"**{dv['alerts_per_host_day_benign']} false alerts per host per day** "
            f"({dv['alerts_per_host_day_total']} alerts per host per day in total). "
            f"Alert labels: {', '.join(f'{k} x{v}' for k, v in dv['alert_labels'].items()) or 'none'}. "
            f"Share of attack alerts carrying the right technique: {dv['label_matches_technique']}.",
            "",
            "Event-level TPR per technique: the deployed verdict, then each score at 1 % / 0.1 % FPR.",
            "",
            "| Technique | Events | Verdict | " + " | ".join(f"`{k}`" for k in SCORE_KEYS) + " |",
            "|---|---|---|" + "---|" * len(SCORE_KEYS),
        ]
        for tech, row in dv["techniques"].items():
            cells = []
            for key in SCORE_KEYS:
                a = res["scores"][key]["0.01"]["techniques"].get(tech, {})
                b = res["scores"][key]["0.001"]["techniques"].get(tech, {})
                cells.append(f"{a.get('event_tpr')} / {b.get('event_tpr')}")
            lines.append(f"| {tech} | {row['positive_events']} | {row['event_tpr']} | " + " | ".join(cells) + " |")
        lines += [
            "",
            "Overall event TPR by score (@1% / @0.1% FPR, achieved FPR in brackets):",
            "",
        ]
        for key, by_fpr in res["scores"].items():
            a, b = by_fpr["0.01"], by_fpr["0.001"]
            lines.append(
                f"- `{key}`: {a['event_tpr']} [{a['achieved_fpr']}] / {b['event_tpr']} [{b['achieved_fpr']}]"
                f"; {a['negatives_at_threshold']} benign events tied on the 1 % threshold"
            )
        lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Score LSADRA detection against labelled data.")
    ap.add_argument("--hosts", type=int, default=20)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--train-days", type=int, default=4)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--datasets", nargs="+", default=["demo", "splunk", "evtx"],
                    choices=["demo", "splunk", "evtx"])
    ap.add_argument("--configs", nargs="+", default=list(CONFIGS), choices=CONFIGS)
    ap.add_argument("--cache-dir", type=Path, default=fetch_datasets.DEFAULT_CACHE)
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1,
                    help="processes for per-run feature extraction")
    ap.add_argument("--label", default="baseline")
    ap.add_argument("--output", type=Path, required=True, help="JSON path; a .md summary is written next to it")
    ap.add_argument("--render-only", action="store_true",
                    help="rewrite the .md summary from an existing --output JSON without running")
    args = ap.parse_args(argv)
    if args.render_only:
        report = json.loads(args.output.read_text(encoding="utf-8"))
        args.output.with_suffix(".md").write_text(render_markdown(report), encoding="utf-8")
        return 0
    if not 0 < args.train_days < args.days:
        ap.error("--train-days must be between 1 and --days - 1")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    _quiet_ml_logs()

    stream, stream_info = build_stream(args)
    rows = to_rows(stream)
    test_start = (bench_events.BASE_DATE + timedelta(days=args.train_days)).timestamp()
    host_days = args.hosts * (args.days - args.train_days)
    logger.info("stream: %d events, %d hosts, %d test host-days", len(rows), args.hosts, host_days)

    results: Dict[str, Any] = {}
    timings: Dict[str, float] = {}
    online = None
    if any(c != "retrained-full" for c in args.configs):
        t0 = time.perf_counter()
        online = online_features(rows, args.workers)
        timings["online_features"] = round(time.perf_counter() - t0, 1)
        logger.info("online replay: %d detection runs, features in %.1fs", len(online[0]), timings["online_features"])
    for cfg in args.configs:
        t0 = time.perf_counter()
        scored = run_config(cfg, rows, test_start, args.seed, online)
        recs = to_records(stream, rows, scored, test_start)
        results[cfg] = metrics.summarize(recs, SCORE_KEYS, FPRS, host_days)
        timings[cfg] = round(time.perf_counter() - t0, 1)
        dv = results[cfg]["deployed_verdict"]
        logger.info("%s: %.1fs, verdict FPR %s TPR %s, %s false alerts/host/day",
                    cfg, timings[cfg], dv["fpr"], dv["event_tpr"], dv["alerts_per_host_day_benign"])

    manifest = fetch_datasets.load_manifest()
    report = {
        "schema": "lsadra-detection-bench/1",
        "meta": {
            "label": args.label,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_sha": _git_sha(),
            "seed": args.seed,
            "datasets": args.datasets,
            "configs": args.configs,
            "fprs": FPRS,
            "versions": _versions(),
            "platform": platform.platform(),
            "seconds": timings,
            "stream": stream_info,
            "sources": {k: {kk: v[kk] for kk in ("repo", "commit", "license")} for k, v in manifest["sources"].items()},
        },
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.output.with_suffix(".md").write_text(render_markdown(report), encoding="utf-8")
    logger.info("wrote %s", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
