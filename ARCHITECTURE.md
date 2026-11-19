# LSADRA architecture

LSADRA (Local Security Anomaly Detection & Risk Assessment) is a local-first,
explainable SIEM. Agents on monitored hosts send events to a single Python core,
which stores them, runs detection, groups anomalies into incidents and explains
them in plain language. Analysts work in a React dashboard.

This page describes what is on `main`. The C4 diagrams (context, containers,
components, and the planned target state) are in
[docs/architecture/c4.md](docs/architecture/c4.md), and the reasoning behind the
larger calls is in the [ADRs](docs/architecture/adr/README.md). If this page and
the code disagree, the code is right and this page is a bug.

## 1. Runtime pieces

| Piece | Where | What it does |
|---|---|---|
| Core API | `lsadra/app.py` (root `server.py` is an alias) | FastAPI app: login, device onboarding, event ingestion, dashboard API, `/ws/alerts` live feed. Started with `lsadra-server` or `python -m lsadra.serve`, which applies the listener policy (loopback by default, TLS required on any other address) |
| Detection worker | `lsadra/detection/detection_worker.py` | One thread in the core process that runs online detection, fed by a bounded queue |
| Background jobs | `lsadra/jobs/scheduler.py` | APScheduler threads in the core process (see section 4) |
| Database | `lsadra/storage/` | SQLite in WAL mode, schema applied by numbered SQL migrations |
| Model files | `data/models/` | Trained detectors, loaded only after their SHA-256 matches an HMAC-authenticated manifest |
| React dashboard | `frontend/` | React 19, Vite, TypeScript, Tailwind; the supported UI. Docker Compose serves the built app from an unprivileged nginx `web` container |
| Endpoint agents | `lsadra/endpoint_agent/linux_agent.py`, `windows_live_agent.py` | Python agents that tail OS logs and send batches |
| Rust collectors | `collectors/` | First cut of the M2 agents: journald (Linux) and Event Log (Windows) sources, disk spool, HTTPS shipper, device key in the OS credential store. Built and tested in CI on three OSes; not shipped in releases yet |

The core is one process. There is no external queue, broker or cron. The
Rust collectors in [`collectors/`](collectors/README.md) replace the Python
agents behind the same event contract, so the core does not change as they take
over
([ADR 0001](docs/architecture/adr/0001-rust-collector-split.md)).

## 2. Code map (`lsadra/`)

| Package | Responsibility |
|---|---|
| `auth.py`, `authz.py`, `admin_cli.py`, `config.py`, `serve.py`, `tls_middleware.py`, `ratelimit.py`, `backup.py` | JWT auth and roles (revocable sessions), per-object access checks, the first-admin command line, environment configuration and boot guards, the listener launcher, TLS enforcement, rate limiting, verified backups |
| `onboarding/` | Registration tokens, device registration, Linux installer, hash-pinned agent files for the install command |
| `ingestion/` | `/api/events/batch` (schema v1), `/api/events/raw` with the multi-source `IngestionManager` and its parsers, device authentication and its verified-credential cache |
| `features/` | Temporal and behavioral feature extraction |
| `security/` | Audit trail, password policy, login throttling, TOTP, TLS listener policy, security headers, file permissions |
| `models/` | Statistical baseline, Isolation Forest, LOF, One-Class SVM, autoencoder, ensemble; model file integrity (`integrity.py`) |
| `llm/` | Guardrails for the optional LLM tier (M4): endpoint and weight pinning, output validation, an action broker that can only propose. No model ships yet |
| `detection/` | Orchestrator, detection worker, model lifecycle (training hygiene, canary gate, rollback), rule registry (`rule_engine.py`, Sigma-shaped metadata), pinned ATT&CK map (`attack_map.py`), canonical event types, rules scorecard, attack classifier, severity, incident manager, drift detector |
| `intel/` | Threat intel in two tiers ([ADR 0004](docs/architecture/adr/0004-intel-two-tier-licensing.md)): a signed, hash-verified bundle (CISA KEV, MITRE ATT&CK) shipped in the package, and an opt-in runtime tier (keyless IP list feeds, AbuseIPDB, local `.mmdb` geolocation); `python -m lsadra.intel` manages it |
| `explainability/` | Narrative builder, log-value sanitizer, threat-intel adapter for narratives, SHAP helpers (not called by the live pipeline) |
| `session/` | Session building and user-journey analysis |
| `jobs/` | Scheduler and IP geolocation from the local `.mmdb` file |
| `storage/` | Database access, migrations, metrics aggregation |
| `api/` | Dashboard REST API, `/api/intel`, investigation and feedback, device revoke and key rotation, `/ws/alerts`, PDF report. `lsadra/ui` is a deprecated import alias for it |

## 3. Event flow

1. **Onboarding.** An analyst creates a single-use registration token in the
   dashboard. The agent or installer exchanges it at
   `POST /api/devices/register` for a device id and an API key. The core keeps
   only a bcrypt hash of the key. The dashboard's install command checks the
   SHA-256 of the installer and the agent before anything runs. See the
   [agent-key threat model](docs/threat-models/agent-keys.md).
2. **Ingestion.** Agents send `POST /api/events/batch` with `X-Device-Id` and
   `X-API-Key`. Every event is validated against
   [`event-schema.v1.json`](docs/contracts/event-schema.v1.json); a violation
   rejects the batch with a `422` that names the field. Raw text logs go to
   `POST /api/events/raw` and are parsed by `IngestionManager`.
3. **Hand-off.** The handler stores the batch and enqueues the device on the
   detection queue. The queue holds distinct devices and coalesces repeat
   batches. When it is full, ingestion answers `503` with `Retry-After` and
   stores nothing, so agent retries never duplicate events. Storage and bcrypt
   work runs in the server's thread pool, never on the event loop.
4. **Detection.** The worker thread runs the orchestrator for the device:
   features, then the statistical baseline, the ML ensemble and the rule
   registry, then severity scoring. Every registered rule runs on the live
   path; a rule at level `medium` or higher raises an alert on its own, a
   lower one only names the technique when the anomaly layers flag the event.
   An anomaly no rule explains is labelled "Unknown Anomalous Activity" with no
   technique. Anomalies are written to the database with the rule that matched.
   The rules' detection rate on the synthetic demo corpus is published in
   [`docs/detection/scorecard.md`](docs/detection/scorecard.md).
5. **Incidents and narratives.** Related anomalies are grouped into incidents.
   The narrative builder explains each one with MITRE ATT&CK mapping (one
   pinned Enterprise release, checked in CI) and, where the owner turned them
   on, what the IP list feeds and AbuseIPDB know about the source IP. Every log-derived value
   passes through the sanitizer first, because logs are attacker-controlled
   input.
6. **Analyst view.** The dashboard reads incidents and metrics over REST and
   receives new alerts over `/ws/alerts`, which authenticates the JWT at the
   handshake. On reconnect it backfills over REST.

## 4. Background jobs

| Job | Interval |
|---|---|
| Metrics pre-aggregation | 5 min |
| Device offline check | 2 min |
| Cross-source correlation | 5 min |
| Lateral-movement scan | 10 min |
| Ingestion health check | 15 min |
| Runtime intel refresh (feeds and AbuseIPDB, only if enabled) | 1 h check |
| Feature drift detection | 24 h |
| IP geolocation from the local `.mmdb` (opt-in) | 24 h |
| Data retention cleanup | `LSADRA_RETENTION_INTERVAL_MINUTES` |

## 5. Performance design

- Ingestion never runs detection inside a request.
- A device key that has passed bcrypt is remembered for
  `LSADRA_DEVICE_AUTH_CACHE_TTL_SECONDS` (default 60 s) as a keyed fingerprint
  bound to the stored hash, and renewed in the background past half its
  lifetime, so a steady sender never waits on bcrypt after its first batch.
- The core shortens Python's thread switch interval
  (`LSADRA_THREAD_SWITCH_INTERVAL_MS`, default 0.5 ms) so a detection run
  hands the GIL back to waiting requests sooner.
- The ingest benchmark in [`benchmarks/`](benchmarks/README.md) measures
  sustained events/s, latency percentiles, event-loop lag and memory against a
  committed baseline. The detection bench in
  [`benchmarks/detection/`](benchmarks/detection/README.md) scores detection
  quality (true-positive rate per ATT&CK technique at a fixed false-positive
  rate); ADR 0007 gates model changes on it.

## 6. Design principles

1. **Explain every alert.** An alert comes with a plain-language narrative and
   the evidence behind it.
2. **Local first.** Core detection, narratives and the bundled threat intel
   need no cloud service and no key. IP geolocation reads a local file. The
   only outside lookups (IP list feeds, AbuseIPDB) are optional and off by
   default.
3. **Logs are hostile input.** Parsers, narratives and any future LLM treat
   log-derived strings as data, never as instructions
   ([threat models](docs/threat-models/README.md)).
4. **Contracts at boundaries.** Agents and the core share a versioned schema,
   not code.
5. **Fail closed.** Outside development mode the core refuses to start
   without a strong JWT secret, self-registration is off
   (`LSADRA_ALLOW_SIGNUP`), the first admin is created from the command line,
   the server listens on loopback unless told otherwise and will not serve
   plain HTTP on any other address, and model files that fail their integrity
   check are not loaded.
6. **Humans approve actions.** Playbooks guide the analyst. LSADRA does not run
   commands on monitored hosts.
