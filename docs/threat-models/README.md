# Threat models

Placeholders for the M0/M1 threat-modeling work — populated with STRIDE-style
models and Mermaid data-flow diagrams.

- **Product threat model** — trust boundaries across collectors, the ingestion
  API, the detection core, storage, and the UI.
- **Agent-key custody** — how endpoint agents obtain, store, and rotate
  credentials (OS-keychain storage on the agent side lands with the Rust agents
  at M2).
- **R8 — prompt-injection defense** — logs are attacker-controlled input to
  parsers, the narrative engine, and (from M4) the LLM and the RAG index.
  - **Boundary rule:** log-derived strings never enter instruction positions. A
    future LLM receives them only inside a data envelope and has no tool access.
  - **M1 (in place):** every log-derived value interpolated into a narrative
    passes through `lsadra/explainability/sanitize.py::clean_field` — NFKC
    normalization, removal of control / zero-width / bidi / tag characters,
    backslash-escaping of markdown-significant characters, and per-field length
    caps with a visible `…(truncated)` marker. Log-derived values are never
    placed inside markdown code spans.
  - **Tests:** `tests/security/test_r8_sanitizer.py` (one class per payload
    family) and `tests/security/test_r8_narrative.py`, which builds every
    narrative from the synthetic `demo/corpus/injection_attempts.jsonl` and
    asserts no raw payload survives, no control characters, unchanged markdown
    structure, and length caps; a static check fails if a template interpolates
    a value that bypasses the sanitizer.
  - **Known limits:** cross-script confusables (e.g. Cyrillic `а`) are not
    folded; bare `www.` text may still be auto-linked by GFM renderers.
  - **M4 (planned):** data-envelope prompt templates, JSON-schema-validated LLM
    output, zero tool access, and index-time sanitization for the RAG store.

> Threat models describe defenses and trust boundaries only. Specific unfixed
> vulnerabilities are tracked privately, never in committed docs.
