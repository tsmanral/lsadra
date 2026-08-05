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

## Diagrams

C4 context / container diagrams (Mermaid) land here as the M0 docs milestone
completes.
