# Contracts

The **event schema** is the versioned contract binding the Rust collectors, the
Python detection core, and the UI. It is the highest-value cross-language
artifact: both sides validate against it, and a breaking change to it is a
breaking change to the system.

- [`event-schema.v1.json`](event-schema.v1.json) — v1 **draft** (JSON Schema).

Versioning: additive changes refine the v1 description; breaking changes create
`event-schema.v2.json` plus a migration note. Collectors and core each declare
which schema version they speak (`schema_version`).
