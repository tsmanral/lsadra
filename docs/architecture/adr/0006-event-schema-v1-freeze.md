# 0006. Event schema v1 freeze and boundary enforcement

- **Status:** Accepted
- **Date:** 2026-09-30
- **Deciders:** project lead (delegated to the implementing agent; architect review)
- **Relates to:** [ADR 0001 — Polyglot split](0001-rust-collector-split.md), [contract README](../../contracts/README.md)

## Context

[`event-schema.v1.json`](../../contracts/event-schema.v1.json) was published at
M0 as a **draft** with a placeholder `$id`. The ingestion API did not enforce it:
the pydantic model had no `schema_version`, accepted naive timestamps and any
string as `source_ip`, silently dropped unknown keys, left `attributes`
unbounded, and accepted any `source_hint` on `/api/events/raw`. Producers sent a
shape that happened to overlap the draft. `/api/events/raw` also stored the
device ID in the `host` column.

The contract is the only thing binding the planned Rust collectors to the Python
core (ADR 0001). A contract the core does not enforce drifts silently, and every
field in it is attacker-controlled input. M1 freezes v1 and makes the ingestion
boundary enforce it.

## Decision

The schema file is the source of truth. The core's pydantic model
(`NormalizedEvent`, `extra="forbid"`) mirrors it, and a test asserts
`model_json_schema()` equals the schema keyword for keyword and that both reject
the same mutated events. Every violation is an HTTP 422 naming the field; the
batch is rejected whole; malformed input is never a 5xx.

| # | Question | Decision | Why |
|---|---|---|---|
| (a) | `schema_version` at the boundary | Required, must equal `"1"`; anything else is a 422. | A version the core never sees cannot be negotiated later. Requiring it now is the cheapest moment — every producer is in this repo. |
| (b) | `device_id` / `user_id` | Schema marks them `readOnly`; the model omits them, so a client that sends either gets a 422. Both are assigned from the authenticated device. | Identity comes from credentials, not from the payload. Silently overwriting a client-supplied value would hide a spoofing attempt or a producer bug; rejecting surfaces both. |
| (c) | `timestamp` | RFC 3339 date-time with a mandatory offset (`Z`/`±HH:MM`), enforced by a shared regex before pydantic's lenient coercion. Naive, epoch-number, space-separated, date-only and leap-second values are rejected. Stored normalized to UTC. | A naive time is ambiguous across collectors in different zones and silently skews every time-window detection. Python cannot represent `:60`, so the contract excludes it rather than advertising what the core cannot store. |
| (d) | `source_ip` | `ipv4` or `ipv6` format, ≤ 45 chars, or `null`. Zone indices (`%eth0`) rejected. | Downstream threat-intel, geo and per-IP features key on this field; a hostname or free text there is either a bug or an injection vector. 45 is the longest IPv6 text form (IPv4-mapped). |
| (e) | `attributes` | ≤ 32 keys; each value ≤ 1024 chars (strings by length, others as compact JSON); whole object ≤ 8 KB as compact UTF-8 JSON. The two size rules JSON Schema cannot express are published as `x-lsadra-*` keywords. | Unbounded `attributes` was the one open door in an otherwise bounded event: memory, storage and later LLM-context amplification. The corpus peaks at 10 keys and ~360 bytes, so the bounds leave generous headroom. |
| (f) | Batch size | Stays ≤ 100 events per request. | Unchanged; it pairs with the per-device rate limiter. Throughput questions belong to the benchmark lane. |
| (g) | `/raw` `source_hint` | Enum `ssh`, `syslog`, `windows`, `network`, `endpoint` (the parser map's keys), or omitted. | An unknown hint silently fell back to auto-detection. The Windows live agent was sending `windows_event`, which matched nothing; it now sends `windows`. |
| (h) | `/raw` `host ← device_id` inversion | Fixed: `host` is the hostname parsed from the log line (SSH, syslog, Windows `Computer`), empty if none. `device_id` stays the authenticated identity. | Two columns holding the same value erased the one piece of source-side identity a raw line carries. |
| (i) | `$id`, DRAFT, compatibility | `$id` is the file's raw GitHub URL on `main`; DRAFT removed; compatibility policy written in the contract README. | The placeholder `$id` was unresolvable. The policy states which edits stay v1 and which force v2. |

Two housekeeping items ride along: the unused `MAX_RAW_LINE_LENGTH` setting
(`LSADRA_V4_MAX_RAW_LINE`, never read) is removed — `/raw` lines share
`MAX_RAW_MESSAGE_LENGTH` (4096) with `raw_message`; and 422 bodies on the
ingestion routes no longer echo the rejected input, because FastAPI's recursive
encoder turned a deeply nested rejected value into a 500.

## Consequences

- **Breaking for out-of-tree producers.** An agent built before this change
  (no `schema_version`, naive timestamps, extra envelope keys such as
  `device_id`/`sent_at`) now receives 422s. All in-repo producers are updated in
  the same change; the Python Linux agent drops a batch on 422 instead of
  retrying it forever.
- **Rust collectors** (M2) validate against the same file with format assertion
  on; `tests/test_contracts.py` is the reference behaviour.
- **Drift is a test failure.** Changing a bound in the schema, the model, or
  `lsadra/config.py` alone fails CI.
- **Future versions** follow the README policy: `attributes` keys and
  documented optional properties stay v1; anything that tightens or removes is
  `event-schema.v2.json` with a dual-version transition window.
