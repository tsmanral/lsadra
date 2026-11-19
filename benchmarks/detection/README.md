# Detection bench

Scores the detection pipeline against labelled data: true-positive rate per
MITRE ATT&CK technique at 1 % and 0.1 % false-positive rate, and alerts per host
per day. It is Phase 0 of the detection-model plan: the baseline every later
model change is measured against. Like the [ingest benchmark](../README.md), it
changes no product behaviour.

- [`run_detection_bench.py`](run_detection_bench.py): the harness.
- [`bench_events.py`](bench_events.py): event sources (synthetic background, demo corpus, Windows adapters).
- [`bench_metrics.py`](bench_metrics.py): thresholds and rates.
- [`datasets.json`](datasets.json): the pinned public subsets (commit, path, sha256, technique).
- [`fetch_datasets.py`](fetch_datasets.py): downloads them into `.cache/` (gitignored) and checks each sha256.
- [`results/`](results/): committed runs, JSON plus a Markdown summary.

## Running it

```bash
pip install -r requirements.txt
pip install evtx                                     # only for the EVTX subsets
python benchmarks/detection/fetch_datasets.py        # ~1.5 MB, optional
python benchmarks/detection/run_detection_bench.py \
    --output benchmarks/detection/results/my-run.json
```

The default run (20 hosts, 14 days) takes a few minutes on four cores. Datasets
that are not cached are skipped with a warning, so the bench also runs offline
on the demo corpus alone (`--datasets demo`). `--workers 1` disables the process
pool; `--configs` picks a subset of the three configurations below.

## What it measures

**Stream.** Each bench host gets seeded synthetic background traffic
(`bench-host-NN`, `*.demo` users, RFC 5737 addresses): logins with the odd
password typo, shell or desktop activity, hourly cron, package updates, outbound
flows, a nightly backup login on some hosts and an occasional on-call admin at
night. About 60 % of hosts are Linux servers and 40 % Windows workstations. The
first `--train-days` days are the training period; everything after is the test
period, and only the test period is measured.

**Attacks.** Each attack instance is injected into one host's test period,
starting on its original UTC time of day and keeping its relative spacing:

| Source | Licence | Use |
|---|---|---|
| `demo/corpus/` (four scenarios; `injection_attempts` is a narrative-engine fixture and is skipped) | this repo | committed |
| [splunk/attack_data](https://github.com/splunk/attack_data), 7 Windows captures | Apache-2.0 | downloaded, never committed |
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), 7 EVTX files | GPL-3.0 | downloaded for testing only, never committed or bundled |

Only aggregate numbers and dataset identifiers reach `results/`; no event from a
public capture is ever written into the repository.

**Labels.** Benign events are negatives. Demo-corpus events labelled malicious or
suspicious with a technique are positives. In a public capture, the event types
listed under `positive_event_types` in `datasets.json` are positives (for
example `auth_failure` in a password spray) and every other event is
*context*: replayed so the features see realistic traffic, but counted as
neither a hit nor a false positive.

**Replay.** Three configurations run against the same stream:

| Config | Features | Training |
|---|---|---|
| `production` | Online: what `run_for_new_events` sees. Agents flush every 3 s or 50 events, a device runs at most once per `DETECTION_THROTTLE_SECONDS` (5 s), and each run takes up to 500 new events, so the 15-minute rolling features only see that run's chunk. | As shipped (`_auto_train` → `retrain`): once a device passes `MIN_BASELINE_EVENTS`, a candidate trains on the most recent `TRAINING_MAX_EVENTS` stored events of every device, minus events already scored as anomalies, with no device above `TRAINING_MAX_DEVICE_SHARE`. Fewer than `MIN_TRAINING_EVENTS` usable events skips the run (30 s retry). The candidate is promoted only if it passes the canary; otherwise the next try waits `RETRAIN_COOLDOWN_SECONDS`. Each attempt is listed under `training` in the results. |
| `retrained-online` | Online, as above. | Every layer trained on all hosts' training days. |
| `retrained-full` | Each device's whole stream at once, so rolling windows see everything. | Every layer trained on the training days. A ceiling for today's algorithms and features. |

The harness calls the real `build_features` and the real
`DetectionOrchestrator._run_layers`; only persistence is bypassed (no model files,
no database), and model training follows `DetectionOrchestrator.train` (the `retrained-*` configs
fit the layers directly and skip the canary, since they measure the algorithms
on clean data).

**Metrics.** For every score (`severity_score`, and each layer's own score), the
threshold for a target FPR is the value that flags at most that share of benign
test events. Per technique the bench reports event-level TPR (share of positive
events above the threshold) and instance-level TPR (share of attack instances
with at least one positive event above it, plus the chance of that happening with
no signal at all). Saturated scores tie many benign events at their maximum; the
bench reports how many sit on the threshold, and a tie never counts as a hit.
The pipeline's own verdict (`is_anomaly`) is reported as deployed: FPR, TPR,
false alerts per host per day, and which ATT&CK label the rule engine attached.

## Limits

- The background is synthetic. Real fleets are noisier, so real false-positive
  rates are at least this high.
- Few instances per technique (one to three), so instance-level TPR is coarse;
  read it together with event-level TPR and the chance column.
- Public captures come from lab domains with their own clocks; they are moved
  onto bench hosts, which changes host names and dates but nothing else.
- The production canary (`LSADRA_CANARY_SCENARIOS`) scores candidates on the
  demo corpus's `ssh_bruteforce` and `injection_attempts`. `ssh_bruteforce` is
  also one of the bench's injected test scenarios, so the production config's
  training has seen a pass/fail signal on part of its test data. The canary
  only accepts or rejects a candidate, it never trains on those events, but read
  the demo-corpus T1110 numbers with that in mind.
- Today's models only see the nine V3 features (time of day, failures and
  successes per source address). Techniques with no authentication signal are
  expected to score at chance; the bench makes that visible rather than hiding it.

## Results

| File | What |
|---|---|
| [`results/baseline-2026-11-18.json`](results/baseline-2026-11-18.json) / [`.md`](results/baseline-2026-11-18.md) | Phase 0 baseline of the pipeline as merged at the time |
| [`results/after-131-2026-11-18.json`](results/after-131-2026-11-18.json) / [`.md`](results/after-131-2026-11-18.md) | `main` after #120, #133 and #131: production training through the canary-gated `retrain` path |
