# Ingest benchmark

Measures what the ingestion path of the current core can sustain. It changes no
product behaviour and optimizes nothing: it is the baseline the M1 storage and
async work is measured against.

- [`run_ingest_bench.py`](run_ingest_bench.py) — the harness.
- [`_bench_server.py`](_bench_server.py) — starts the unmodified `server:app` on a throwaway data directory.
- [`baseline-2026-09-30.json`](baseline-2026-09-30.json) — the committed baseline (detection on and off, 1/10/20 devices, two runs each).
- [`baseline-2026-09-30-detection-ceiling.json`](baseline-2026-09-30-detection-ceiling.json) — supplementary: detection-on throughput ceiling (10/20 devices, two runs).
- Load generator: `scripts/seed_demo.py --rate/--duration/--devices` (rate mode), which the harness imports.

## Running it

```bash
pip install -r requirements.txt
python benchmarks/run_ingest_bench.py                       # full baseline, ~25 min
python benchmarks/run_ingest_bench.py --detection on --devices 10 20 \
    --stop-on throughput                                    # detection-on ceiling, ~20 min
python benchmarks/run_ingest_bench.py --detection off --devices 1 --rates 50 \
    --duration 5 --min-requests 1 --repeats 1 --output /tmp/check.json   # 30 s sanity check
```

Run on an otherwise idle machine. The harness never touches `data/`: each run
gets a fresh temp directory with its own database and model store.

## Method

**Server.** One `uvicorn` process with its defaults (one worker, as the
Dockerfile runs it), `LSADRA_DEV_MODE=true`, fresh SQLite database per run.
Detection-off runs also set `LSADRA_BENCH_SKIP_DETECTION=true`, which skips
`run_for_new_events` on the ingestion request path; the server refuses to boot
with that flag outside dev mode, and the harness checks that the running
server reports the mode it asked for.

**Load.** Everything goes through the real API: register a user, mint
registration tokens, onboard N devices (`/api/devices/register`), then
`POST /api/events/batch` with each device's own API key. Batches are 100 events
(the server maximum). Payloads cycle through four pinned corpus files —
`ssh_bruteforce`, `persistence_new_service`, `data_movement_offhours`,
`benign_background` (188 events) — pinned so the workload does not change when
new corpus files are added. Each event is stamped with the send time.

The load generator is a single asyncio thread and runs **open loop**: batches are
sent on a fixed schedule regardless of whether earlier ones have returned, so a
server that falls behind shows up as latency and a stretched completion window,
not as a quietly reduced offered rate. Batches go round-robin across devices.

**Rate-limit arithmetic.** The ingest limiter allows 60 batch requests per
minute per device, i.e. 100 events/s per device. Every step stays at or under
95 % of that, so the limiter is never the bottleneck being measured (0 × 429 in
every run). Reaching 1 000 events/s therefore needs at least 11 devices; the
highest rate offered is 1 900 events/s (20 devices × 95). Device registration
is limited to 5/min per client IP, so the harness registers its fleet from
loopback addresses `127.0.0.1…127.0.0.5` (four devices per address) rather
than waiting; where those aliases do not exist (macOS by default) it waits the
limiter out instead. The baseline runs registered from `127.0.0.2…127.0.0.6`;
the source address of registration has no effect on ingestion.

**Warm-up.** One full batch per device before measuring. With detection on
this includes the one-off model training (≈ 40–85 s), which is reported but not
part of any step.

**Per step** (15 s, lengthened so every step sends at least 12 requests):

| Metric | Source |
|---|---|
| `sustained_ev_s` | events accepted ÷ max(schedule length, time the last response arrived). The final requests' own latency is inside that window, so a server that keeps up reads 1–2 % under the offered rate. |
| `latency_ms` p50/p95/p99 | client-side, send to response, successful requests only |
| `rss_mb` | server process tree RSS (psutil), sampled every 0.5 s — max over the step |
| `loop_lag_ms` p50/p99 | dev-mode sampler in `server.py`: an asyncio task sleeps 100 ms and records how late it woke up; read back through `/api/health` (`benchmark` key, dev mode only) |
| `server_cpu_cores_avg` | server CPU seconds ÷ wall seconds |

Before each step the harness waits until the server is idle (CPU < 25 % of a
core and no loop-lag sample ≥ 50 ms for 2 s), so one step's backlog does not
leak into the next.

**Stopping rule.** A step is *degraded* if sustained < 90 % of offered, p99 >
1 000 ms, loop-lag p99 > 500 ms, or any request was rate-limited, failed,
dropped or abandoned. By default a device count's ladder ends at its first
degraded step; `--stop-on throughput` continues until the core stops keeping up.
These are sweep controls, not pass/fail gates.

**Loop-lag floor.** Measured with no load after warm-up: p50 8.5–9.3 ms, p99
10.6–13.3 ms across all six runs. On Windows `asyncio.sleep` wakes on the system timer
(~15.6 ms granularity), so single-digit-millisecond lag is timer noise, not
blocking. The same harness on Linux should show a much lower floor.

## Machine

| | |
|---|---|
| CPU | Intel Core Ultra 9 185H — 16 cores / 22 threads (laptop) |
| RAM | 31.4 GB |
| OS | Windows 11 Pro 10.0.26200 |
| Python | 3.14.3 (server event loop: asyncio; uvloop does not run on Windows) |
| Key libraries | fastapi 0.141.1, uvicorn 0.52.1, scikit-learn 1.9.0, pandas 3.0.5 |
| Code | `main` @ `90aee39` + this harness (the three measurement hooks only) |

Laptop power plan and thermal state were not controlled. Run-to-run spread
below is the honest error bar.

## Results (2026-09-30)

Two runs per configuration, shown as `run 1 / run 2`. Full per-step data in the JSON.

### Detection off — storage + auth path only

No step degraded; every request succeeded (0 × 429, 0 errors). The ladder ends
where the rate limiter would start to bind, not where the server failed.

| Devices | Offered ev/s | Sustained ev/s | p50 ms | p95 ms | p99 ms | Loop lag p50 / p99 ms | RSS MB | Server CPU (cores) |
|---:|---:|---|---|---|---|---|---|---|
| 1 | 95 | 95 / 95 | 280 / 281 | 298 / 308 | 302 / 312 | 8.7 / 10.9 · 8.8 / 19.0 | 106 / 107 | 0.25 / 0.25 |
| 10 | 100 | 100 / 100 | 252 / 309 | 311 / 347 | 320 / 358 | 8.6 / 21.4 · 8.8 / 15.8 | 108 / 108 | 0.23 / 0.27 |
| 10 | 500 | 497 / 496 | 284 / 240 | 320 / 302 | 335 / 320 | 9.0 / 24.2 · 8.9 / 27.5 | 109 / 109 | 1.32 / 1.11 |
| 10 | 950 | 939 / 940 | 258 / 259 | 288 / 280 | 305 / 291 | 9.3 / 24.9 · 9.1 / 24.4 | 110 / 110 | 2.30 / 2.26 |
| 20 | 500 | 500 / 496 | 212 / 276 | 296 / 314 | 311 / 320 | 9.0 / 22.7 · 9.0 / 24.5 | 112 / 112 | 1.05 / 1.27 |
| 20 | 1 000 | 987 / 985 | 258 / 262 | 296 / 298 | 306 / 308 | 8.6 / 28.0 · 9.1 / 24.8 | 113 / 113 | 2.33 / 2.44 |
| 20 | 1 500 | 1 476 / 1 480 | 259 / 250 | 277 / 276 | 292 / 287 | 9.3 / 32.8 · 9.3 / 30.1 | 107 / 106 | 3.54 / 3.45 |
| 20 | 1 900 | 1 872 / 1 873 | 255 / 249 | 289 / 271 | 326 / 285 | 8.9 / 35.8 · 9.4 / 30.4 | 107 / 107 | 4.34 / 4.37 |

Lower rungs (25/50/250 ev/s) behave the same: p50 205–290 ms, p99 275–351 ms,
loop-lag p99 11–29 ms.

### Detection on — the inline ML path

Every configuration degraded at the lowest rung offered (25 ev/s), both runs.
Throughput kept up; latency and the event loop did not.

| Devices | Offered ev/s | Sustained ev/s | p50 ms | p95 ms | p99 ms | Loop lag p50 / p99 ms | RSS MB | Server CPU (cores) |
|---:|---:|---|---|---|---|---|---|---|
| 1 | 25 | 25 / 25 | 1 527 / 1 475 | 4 523 / 4 933 | 4 639 / 4 990 | 8.8 / 4 081 · 8.7 / 4 000 | 496 / 497 | 0.37 / 0.37 |
| 10 | 25 | 25 / 25 | 2 361 / 2 201 | 3 409 / 3 822 | 4 181 / 4 520 | 8.9 / 2 300 · 8.9 / 2 001 | 497 / 497 | 0.44 / 0.40 |
| 20 | 25 | 25 / 25 | 2 261 / 2 216 | 2 540 / 2 558 | 2 624 / 2 559 | 8.6 / 2 084 · 8.8 / 2 142 | 497 / 498 | 0.41 / 0.36 |

Supplementary ceiling sweep (`--stop-on throughput`, 10 and 20 devices):

| Devices | Offered ev/s | Sustained ev/s | p99 ms | Loop lag p99 ms | Server CPU (cores) |
|---:|---:|---|---|---|---|
| 10 | 50 | 48 / 50 | 2 890 / 1 830 | 2 379 / 1 587 | 0.66 / 0.55 |
| 10 | 100 | 46 / 50 | 24 515 / 22 593 | 16 302 / 14 097 | 0.74 / 0.77 |
| 20 | 50 | 49 / 46 | 2 619 / 7 057 | 2 255 / 4 206 | 0.63 / 0.70 |
| 20 | 100 | 23 / 53 | 55 946 / 18 995 | 28 119 / 11 640 | 0.42 / 0.75 |

### Re-check after rebasing onto `0cc230f`

The baseline was measured on `90aee39`. Before merge this branch was rebased
onto `0cc230f`, which adds boundary enforcement of event schema v1 (payloads
now carry `schema_version`) and the narrative sanitizer. Spot-check, one run
each, same machine:

| Detection | Devices | Offered ev/s | Sustained ev/s | p50 / p95 / p99 ms | Loop lag p50 / p99 ms |
|---|---:|---:|---:|---|---|
| off | 20 | 1 000 | 988 | 261 / 287 / 295 | 9.2 / 28.0 |
| off | 20 | 1 900 | 1 873 | 251 / 272 / 288 | 8.8 / 32.6 |
| on | 10 | 25 | 25 | 2 192 / 2 424 / 2 512 | 8.7 / 1 934 |

All within the run-to-run spread above, so the committed baseline stands for
the rebased code.

## What the numbers say

1. **With detection off, ≥ 1 000 events/s is reached** at 20 devices (987 / 985
   ev/s at 1 000 offered) and holds to 1 872 ev/s at 1 900 offered with no
   errors. The limit of the sweep was the per-device rate limiter, not the
   server. At 10 devices the limiter caps the fleet at 950 ev/s (939 / 940
   sustained).
2. **With detection on, the ceiling is ≈ 50 events/s**, independent of fleet
   size, and latency is already seconds at 25 ev/s. Server CPU stays under one
   core while the loop stalls for 2–5 s at a time: detection runs inline on the
   event loop and serializes every request behind it. Loop-lag p99 goes from
   ≈ 11–36 ms (detection off) to ≈ 2 000–4 000 ms (detection on) at the same
   25 ev/s — detection, not storage, is what blocks the loop today.
3. **Request latency with detection off is ≈ 250–300 ms at every rate** and
   barely moves with load. A sequential probe (one request per second, 20 each,
   same server build) attributes it: `/api/health` 3.6 ms median, a device-authenticated
   read with no DB write (`/api/events/stats`) 264 ms, a 100-event batch 283 ms.
   So ≈ 93 % of batch latency is device API-key verification (bcrypt, per
   request) and ≈ 20 ms is validation + insert. That verification runs in the
   FastAPI threadpool, which is why the loop stays responsive and throughput
   scales with cores (4.4 cores busy at 1 900 ev/s). *Inference:* no storage
   change can bring detection-off p99 under ~260 ms while every batch pays a
   full bcrypt verification.
4. **RSS**: ≈ 105–113 MB with detection off; ≈ 485–500 MB once the detection
   stack is loaded and trained. It did not grow across steps.
5. **Not measured here:** writer-lock contention. The harness's load does not
   trigger `database is locked`; concurrent-writer behaviour is covered by the
   storage contract suite, not this benchmark.
