# Contracts

The **event schema** is the versioned contract binding the Rust collectors, the
Python detection core, and the UI. It is the highest-value cross-language
artifact: both sides validate against it, and a breaking change to it is a
breaking change to the system.

- [`event-schema.v1.json`](event-schema.v1.json) — v1, **frozen 2026-09-30**
  (JSON Schema 2020-12). Rationale: [ADR 0006](../architecture/adr/0006-event-schema-v1-freeze.md).

## Where it is enforced

`POST /api/events/batch` validates every event against v1 before anything is
written. The core's pydantic model (`NormalizedEvent` in
`lsadra/ingestion/api_ingestion.py`) mirrors the schema, and
`tests/test_contracts.py` fails if the two drift — keyword for keyword, and
behaviourally (one mutated event per rule must be rejected by both).

A violation is **HTTP 422** whose `detail[].loc` names the offending field, e.g.
`["body", "events", 3, "source_ip"]`. The batch is rejected whole; nothing from
it is stored. The 422 body carries `type`, `loc` and `msg` only — it never echoes
the rejected input. Malformed JSON is a 4xx too; the ingestion boundary never
answers 5xx to bad input.

Validators outside the core (collectors, CI tooling) must enable JSON Schema
**format assertion** (`ipv4`, `ipv6`, `date-time`); it is optional in 2020-12
and off by default in most libraries.

## v1 rules

| Field | Rule |
|---|---|
| envelope | `{"events": [...]}`, at most 100 events, no other keys |
| `schema_version` | required, exactly the string `"1"` |
| `timestamp` | required, RFC 3339 date-time **with offset** (`Z` or `±HH:MM`); naive, epoch-number, space-separated, date-only and leap-second (`:60`) values are rejected; stored normalized to UTC |
| `event_type` | required, ≤ 64 chars |
| `device_id`, `user_id` | `readOnly`: assigned by the server from the authenticated device; an event that carries either is rejected |
| `host` | ≤ 255 chars |
| `effective_username` | ≤ 128 chars |
| `source_ip` | IPv4 or IPv6 literal (≤ 45 chars, no zone index) or `null`; hostnames and `""` are rejected |
| `raw_message` | ≤ 4096 chars |
| `attributes` | object, ≤ 32 keys; each string value ≤ 1024 chars, each non-string value ≤ 1024 chars as compact JSON; whole object ≤ 8192 bytes as compact UTF-8 JSON |
| anything else | rejected (`additionalProperties: false`) |

The two `attributes` size rules that standard JSON Schema cannot express are
published as `x-lsadra-maxValueLength` and `x-lsadra-maxSerializedBytes`; the
core enforces them.

`POST /api/events/raw` takes unparsed lines and is not an event-schema endpoint,
but shares the boundary rules: `{"lines": [...]}` with at most 100 lines,
`raw_line` ≤ 4096 chars, `source_hint` one of `ssh`, `syslog`, `windows`,
`network`, `endpoint` (or omitted for auto-detection), no other keys. A line
that no parser recognizes is counted in `parse_errors` of a 200 response rather
than rejected. The stored `host` is the hostname found in the log line (empty
if the line carries none), never the device ID.

## Compatibility policy

v1 is frozen. Changes that do **not** need a new version:

- **Descriptions and examples** — anything that does not change which documents
  validate.
- **New `attributes` keys** — at any time. `attributes` is the v1 extension
  point for source-specific data, within its size bounds.
- **New optional top-level properties** — only as a schema edit that lands in
  the same PR as core support. Because v1 sets `additionalProperties: false`, a
  collector must not send a new property until the core it talks to accepts it.

Changes that require `event-schema.v2.json`, a migration note, and a core that
accepts both `schema_version` values during the transition:

- adding a required property, removing or renaming a property;
- tightening any bound or format (a shorter `maxLength`, a narrower type);
- changing the meaning of an existing field.

Loosening a bound is harmless for producers but can break consumers that rely on
it; treat it as a v2 change unless every consumer lives in this repository and
is updated in the same PR.

Collectors and core each declare which version they speak through
`schema_version`; the core rejects versions it does not implement.
