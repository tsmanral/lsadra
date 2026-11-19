# Architecture

LSADRA is a polyglot system: lightweight **Rust** endpoint collectors feed a
**Python** detection core (statistical + ML layers), explainability, threat-intel
enrichment, and a FastAPI + dashboard surface. The language boundary is a
versioned contract, not shared code — see
[ADR 0001](adr/0001-rust-collector-split.md) and the
[event schema](../contracts/event-schema.v1.json).

## Decision records

See [adr/](adr/README.md). Start with:

- [0001 — Polyglot split (Rust collectors, Python core)](adr/0001-rust-collector-split.md)
- [0002 — Product name (LSADRA)](adr/0002-product-name.md)
- [0003 — Apple-less development strategy](adr/0003-apple-less-strategy.md)
- [0004 — Threat-intel two-tier architecture & licensing](adr/0004-intel-two-tier-licensing.md)
- [0006 — Event schema v1 freeze and boundary enforcement](adr/0006-event-schema-v1-freeze.md)
- [0007 — Detection stack: rules, entity baselines, small ONNX models](adr/0007-detection-stack.md)
- [0008 — Lite and Team line](adr/0008-lite-team-line.md)

## Diagrams

[C4 diagrams](c4.md): system context, containers, the components of the Python
core, and the planned target state. The repository's `ARCHITECTURE.md` walks
through the same system in prose (code map, event flow, background jobs).
