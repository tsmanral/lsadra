# LSADRA Documentation

**LSADRA — Local Security Anomaly Detection & Risk Assessment.** A local-first,
explainable, open-source SIEM.

> Docs are plain, relative-linked Markdown (no wikilinks) so they render on
> GitHub. Diagrams use Mermaid. Never paste real log excerpts into docs — use
> clearly-synthetic or `--demo`-flagged examples only.

## Map

- [Architecture](architecture/README.md) — system design and decision records (ADRs).
- [Threat models](threat-models/README.md) — product threat model, agent-key custody, prompt-injection defense.
- [Contracts](contracts/README.md) — the versioned event schema binding collectors, core, and UI.
- [Security](security/README.md) — reporting and posture.
- [Contributing](contributing/README.md) — how to contribute.

Publication of the rendered docs site (MkDocs Material) is gated on the product
name decision — see [ADR 0002](architecture/adr/0002-product-name.md) (gate D1).
