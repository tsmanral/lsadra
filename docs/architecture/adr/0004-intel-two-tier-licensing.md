# 0004. Threat-intelligence two-tier architecture & licensing

- **Status:** Accepted (policy; build at M4)
- **Date:** 2026-07-24
- **Deciders:** project lead

## Context

Threat intelligence must enrich detections without (a) incurring recurring cost,
(b) adding a third-party service to a trust-critical path, or (c) redistributing
license-encumbered data inside release assets (a DMCA / key-revocation risk).

## Decision

Split intel into **two tiers**:

- **Bundled tier (redistributable):** public-domain / attribution-permitted feeds
  — CISA KEV, CISA advisories, MITRE ATT&CK (STIX), NVD/CVE. Shipped as a
  versioned, hash-verified `intel-YYYYMMDD.sqlite` with a per-source manifest and
  `LICENSES.md`. The manifest is **signed** — the intel DB is a poisoning target
  that feeds every downstream detection and the LLM narrative engine. This tier
  must be fully functional with **zero user API keys**.
- **Runtime tier (never redistributed):** keyed sources (AbuseIPDB, OTX,
  abuse.ch, Spamhaus, MaxMind GeoLite2). Written only to a gitignored
  `intel_runtime.db` from the user's own free keys; never committed, never in a
  release asset.

Fetchers use conditional GETs and scheduled Actions. The prior third-party
scraping dependency is removed entirely (self-hosted `requests` + parser for
CISA advisory bodies, cross-checked against the RSS index as a provenance guard).

## Consequences

- Redistribution licensing is contained to the bundled tier's explicit allowlist.
- Bundled-tier integrity depends on manifest signing + hash verification before load.
- Post-launch, intel moves to a separate data repo / release track (hourly/daily
  churn would bloat the code repo); EPSS enrichment is a later addition.
