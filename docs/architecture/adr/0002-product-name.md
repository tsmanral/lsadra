# 0002. Product name — LSADRA

- **Status:** Accepted (pending formal trademark/domain clearance — gate **D1**)
- **Date:** 2026-07-24
- **Deciders:** project lead

## Context

The project needs a durable, legally-defensible public name before any public
launch, package, or domain. A name that appears in public artifacts and later
fails clearance is expensive to unwind (packages, domains, SEO, docs).

## Decision

Adopt **LSADRA — Local Security Anomaly Detection & Risk Assessment**. It states
the product's stance directly (local-first, explainable anomaly detection with
risk scoring) and is already applied across the codebase, README, and container
image.

## Clearance checklist (gate D1 — complete before public launch)

- [ ] USPTO TESS search (word mark + likely classes)
- [ ] EUIPO / national registry search
- [ ] Company/registry collision check
- [ ] Domain availability + acquisition
- [ ] Package-registry collision check (PyPI, crates.io, npm, GHCR)
- [ ] Social handle availability

Until D1 is signed, the name is used internally and in the repo but **not**
promoted through a public launch or the published docs site.

## Consequences

- Public MkDocs publication and any launch announcement are gated on D1.
- If clearance fails, the rename is contained to metadata (the code isolates the
  name); this ADR is **superseded** by a new record rather than edited.
