# 0007. Detection stack: rules, entity baselines and small ONNX models, gated by a bench

- **Status:** Accepted
- **Date:** 2026-11-18
- **Deciders:** project lead (approved the detection-model plan on 2026-11-18)
- **Relates to:** [ADR 0001 — Polyglot split](0001-rust-collector-split.md), [ADR 0006 — Event schema v1](0006-event-schema-v1-freeze.md), [detection bench](../../../benchmarks/detection/README.md)

## Context

Detection today is three unsupervised layers OR-ed with hard-coded rules
(`lsadra/detection/detection_orchestrator.py`):

1. a per user and device z-score over nine features, anomalous above z = 3;
2. a majority vote of Isolation Forest, Local Outlier Factor and One-Class SVM,
   each set to flag 5 % of training data;
3. a PyTorch autoencoder, anomalous above the 95th percentile of training error;

plus Python rules that force an alert and attach an ATT&CK technique. An audit of
`main` at `1be6e3f` found:

- **Never measured.** No layer had been scored against labelled attacks.
- **Narrow input.** The models see nine V3 features (time of day, failures and
  successes per source address). The fourteen V4 features (network, process,
  cross-source) reach the rules only.
- **No calibration.** OR-ing several detectors that each flag about 5 % of
  normal traffic yields an alert rate set by configuration, not by risk.
- **Trained once, on little.** One global model is trained on the first device
  to pass baselining, from its first ≤ 500 events, and never retrained. Drift is
  logged, nothing acts on it.
- **Explanations not wired.** `shap_values` was always empty although the README
  claimed SHAP attribution.
- **Pickled models.** Models persist as joblib/torch pickles, which execute code
  when loaded.
- **PyTorch** is installed for a model of a few kilobytes.

The established detection products converge on the same pattern: a large
rule library, per-entity behaviour baselines feeding a risk score, small
distilled or tree models run through ONNX Runtime on the endpoint, and an LLM
that triages and explains on top of that evidence, never in place of it.

## Decision

Detection moves to five layers, each with one job, all CPU-only, and every
model file shipped as ONNX (or GGUF for the optional LLM) with its SHA-256 in a
signed manifest. No pickle is loaded.

| Layer | Replaces | With |
|---|---|---|
| 1. Rules | Hard-coded Python rules | Sigma rules compiled with pySigma into a local matcher; rule attribution kept with the rules |
| 2. Entity behaviour | Global z-score on nine features | Per user, host and source baselines: robust median and MAD by hour of week, plus first-seen and rarity counters |
| 3. Unsupervised scorer | IF + LOF + OC-SVM vote, PyTorch autoencoder | Isolation Forest kept, ECOD added; LOF, One-Class SVM and the autoencoder dropped |
| 4. Supervised classifier | Nothing | LightGBM over the full feature set, trained on public labelled attack data, explained with its built-in TreeSHAP contributions |
| 5. Risk and verdict | OR of all layers | Calibrated stacking into a 0-100 entity risk score that accumulates with decay; alert on threshold; reviewed suppression rules |

A small sequence model over process events follows only once the collectors
send process events.

**Gate.** Nothing replaces the current pipeline until it beats it on the
[detection bench](../../../benchmarks/detection/README.md): TPR at 1 % and
0.1 % FPR per ATT&CK technique, and alerts per host per day, against the
committed baseline. The lite tier's budget is five or fewer false alerts per host
per day and models under 20 MB in total, within the M1 throughput gate.

**Rollout.** Each new layer first runs in shadow mode: it scores every event
and logs its verdict beside the current one but raises no alert until its gate
passes. The current ensemble stays available behind a legacy detector setting
for one release after the swap.

**Data.** splunk/attack_data (Apache-2.0) is the main training and test source,
pulled as pinned subsets. EVTX-ATTACK-SAMPLES (GPL-3.0) is test-only and never
bundled or committed. Benign background from real machines stays on the machine
it came from; only aggregate numbers are committed.

**LLM tier** (optional, never on the detection path; approved the same day):
the default local model moves from Qwen2.5-1.5B to Qwen3.5-2B (4B where memory
allows); Foundation-Sec-8B-Reasoning is an opt-in for 16 GB machines; the RAG
embedder defaults to bge-small with EmbeddingGemma as an option; the startup
tier may enable a bring-your-own-key cloud triage agent over sanitized incident
JSON, with a human approving any response action. The lite tier keeps its
"no API keys required" promise.

## Consequences

- **Lighter install.** Dropping the autoencoder removes PyTorch; ONNX Runtime
  replaces it. The `shap` package is not needed once LightGBM's own
  contributions provide attributions.
- **Same files everywhere.** ONNX models run in the Python core now, in the Rust
  collectors later (ADR 0001) and on Android.
- **Explanations become real** for the supervised layer; until it ships the
  README does not claim SHAP attribution.
- **A labelled bench is part of the codebase.** Detection changes are reviewed
  against numbers. A CI job rerunning a small public subset on changes under
  `lsadra/models/`, `lsadra/detection/` or the rules is follow-up work.
- **Schema.** Process and command-line features use the bounded `attributes`
  map first; a v2 event schema, if needed, is its own ADR (ADR 0006 policy).
- **Licences to respect:** GPL-3.0 test data is never bundled; Sigma rules keep
  their Detection Rule License attribution; the Foundation-Sec model's NOTICE is
  checked before the product links a download.
- **Risk:** a classifier trained on lab data can misfire on real machines.
  Shadow mode, the private benign-background measure and the risk layer sit
  between it and an alert. Analyst feedback only adds reviewed suppression
  rules; it never retrains a model directly, so it is not a poisoning path.
