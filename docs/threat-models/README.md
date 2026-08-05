# Threat models

Placeholders for the M0/M1 threat-modeling work — populated with STRIDE-style
models and Mermaid data-flow diagrams.

- **Product threat model** — trust boundaries across collectors, the ingestion
  API, the detection core, storage, and the UI.
- **Agent-key custody** — how endpoint agents obtain, store, and rotate
  credentials (OS-keychain storage on the agent side lands with the Rust agents
  at M2).
- **R8 — LLM prompt-injection defense** — logs are attacker-controlled input to
  parsers, the LLM narrative engine, and the RAG index; defenses and their tests
  are documented here (cross-cutting, P0 at M1).

> Threat models describe defenses and trust boundaries only. Specific unfixed
> vulnerabilities are tracked privately, never in committed docs.
