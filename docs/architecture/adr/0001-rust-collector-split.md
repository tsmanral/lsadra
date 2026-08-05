# 0001. Polyglot split — Rust collectors, Python core

- **Status:** Accepted
- **Date:** 2026-07-24
- **Deciders:** project lead

## Context

LSADRA has two workloads with opposite constraints:

- **Endpoint collection** must be lightweight, static, and safe to run as a
  privileged, long-lived process on many machines — low memory, no GC pauses, no
  heavy runtime to ship or exploit.
- **Detection, ML, explainability, and the API/UI** benefit from Python's data
  and ML ecosystem (pandas, scikit-learn, torch, SHAP, FastAPI).

A single language forces a bad trade: Python agents are heavy and awkward to
distribute safely; a Rust core would abandon the ML ecosystem.

## Decision

Adopt a **polyglot split**:

- **Rust** for endpoint collectors / agents (lands at M2 with the first Cargo
  workspace), distributed as signed static binaries.
- **Python** for the detection core, ML/explainability, threat-intel, and the
  API + dashboard.
- The two are bound by a **versioned event contract**
  ([`docs/contracts/event-schema.v1.json`](../../contracts/event-schema.v1.json)),
  not by shared code.

## Consequences

- The language boundary becomes a **stability contract**: the event schema is
  versioned and both sides validate against it; breaking it is a breaking change.
- Two toolchains and two CI lanes (Rust hooks/clippy enter at M2).
- Agent supply-chain security (signing, update channel) is first-class (M5).
- Until M2 a thin Python agent exists as a stopgap; it is not the shipping agent.
