# Demo corpus and seeder

A dev-mode LSADRA core boots with an empty database — there is nothing to look at
and nothing to test detection against. This directory is the fix: a small,
committed, **labeled synthetic** event corpus plus a seeder that replays it
through the real API.

> **All data here is fabricated.** Hosts are `demo-host-NN`, every user name ends
> in `.demo`, and every address comes from the documentation ranges reserved by
> [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) (`192.0.2.0/24`,
> `198.51.100.0/24`, `203.0.113.0/24`) and
> [RFC 3849](https://www.rfc-editor.org/rfc/rfc3849) (`2001:db8::/32`).
> No real log line, host, account, or address appears in this repository.

## Quick start

```bash
# terminal 1 — core in dev mode
LSADRA_DEV_MODE=true python server.py

# terminal 2 — seed it
python scripts/seed_demo.py
```

That is the whole flow: a dev boot plus one command yields a populated dashboard.

## What the seeder actually does

`scripts/seed_demo.py` writes **nothing** to the database directly. It drives the
same HTTP surface a real agent uses:

1. `POST /api/auth/register` (first run only) then `POST /api/auth/login` — JWT.
2. `POST /api/dashboard/generate-token` — single-use registration token.
3. `POST /api/devices/register` — onboards the demo device, receives the API key
   that is returned exactly once.
4. `POST /api/events/batch` — batched replay with `x-device-id` / `x-api-key`,
   which runs online detection per batch.

So a successful seed is evidence that onboarding, JWT auth, device API-key auth,
batch validation, the per-device rate limiter, and the detection path all work
end to end — not just that the seeder works.

Before sending, the corpus is **time-shifted** so its newest event lands at
*now*, preserving relative spacing (a brute-force burst stays a burst).

### Useful flags

| Flag | Purpose |
|---|---|
| `--url` | Target core (default `http://127.0.0.1:8000`) |
| `--scenarios ssh_bruteforce benign_background` | Replay a subset |
| `--batch-size N` | Events per request (server max 100) |
| `--pace 0.5` | Fraction of the server's request-rate limit to use |
| `--dry-run` | Parse, label-count and time-shift only; send nothing |

The default pace stays under the server's 60-requests-per-minute per-device
limiter on purpose — seeding a demo should not trip the defense it is exercising.

## Scenarios

Each file is [JSON Lines](https://jsonlines.org/): one event per line, validated
against [`docs/contracts/event-schema.v1.json`](../docs/contracts/event-schema.v1.json)
by `tests/test_demo_corpus.py`.

| File | Events | Story | Labels |
|---|---|---|---|
| `ssh_bruteforce.jsonl` | 48 | Legitimate key-based logins, then a password-spray burst from `198.51.100.37` walking a user list, one successful compromise, then hands-on-keyboard recon | 4 benign / 44 malicious |
| `persistence_new_service.jsonl` | 35 | Windows-flavoured: routine service and process noise, an encoded-command execution, a bogus service installed from a temp path, a scheduled task, then a C2 beacon to `203.0.113.44` | 15 benign / 3 suspicious / 17 malicious |
| `data_movement_offhours.jsonl` | 41 | `svc-backup.demo` reads far past its daytime baseline at ~02:00, stages an archive, then pushes hundreds of MB to `203.0.113.90` | 16 benign / 13 suspicious / 12 malicious |
| `benign_background.jsonl` | 64 | The negative-class control set: business-hours logins, package updates, cron, boot-time services, ordinary traffic — plus deliberate near-misses (one isolated failed login, one modest after-hours backup) | 64 benign |

Techniques referenced (MITRE ATT&CK, for orientation only — this is not a
detection-coverage claim): T1110.001, T1078, T1543.003, T1053.005, T1071.001,
T1005, T1560.001, T1041.

## Ground-truth labels

Every event carries its label inside `attributes`, which keeps each line valid
against the v1 event schema (the contract sets `additionalProperties: false` at
the top level, so a new top-level field would break collector/core alignment):

```json
"attributes": {
  "service": "sshd",
  "ground_truth": {
    "label": "malicious",
    "scenario": "ssh_bruteforce",
    "phase": "credential-spray",
    "attack_technique": "T1110.001"
  }
}
```

| Field | Meaning |
|---|---|
| `label` | `benign`, `suspicious`, or `malicious` |
| `scenario` | Always equals the file stem |
| `phase` | Stage within the scenario (`baseline-legitimate-access`, `successful-compromise`, …) |
| `attack_technique` | MITRE ATT&CK id, or `null` for benign events |

The labels survive ingestion — they are stored with the event — so the same
corpus serves three purposes: demo data, a detection-quality fixture (precision
measured against the benign control set), and the load fixture for the M1
benchmark harness.

## Hygiene rules for future edits

`tests/test_demo_corpus.py` enforces these; they are not suggestions.

- Never paste a real log line. Invent them.
- Hosts stay `demo-host-NN`; user names stay `*.demo`; addresses stay inside the
  documentation ranges above.
- Every event needs a `ground_truth` block, and `benign_background.jsonl` must
  stay 100% benign or false-positive measurement becomes meaningless.
- Timestamps ascend within a file and stay on the synthetic January-2026 base
  date — the seeder does the shifting.
- Only generator code and the corpus are committed. Databases the seeder
  produces are gitignored and never leave your machine.
