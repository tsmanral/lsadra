# 0008. Where Lite ends and Team begins

- **Status:** Accepted
- **Date:** 2026-11-18
- **Deciders:** project lead
- **Relates to:** [ADR 0004 — Threat-intel two tiers](0004-intel-two-tier-licensing.md), [ADR 0006 — Event schema v1 freeze](0006-event-schema-v1-freeze.md)

## Context

LSADRA is planned as two editions: **Lite**, free and AGPL-3.0 in this public
repository, for individuals and homelabs; and **Team**, a paid edition in a
private repository, for startups and managed service providers. The line between
them was never written down, and the code moved past the early assumption that
Lite would be one device with no roles. Today this repository is a multi-device
server with role-based access (`ADMIN`, `ANALYST`, `VIEWER`), and recent work
already shaped it for a single owner: open self-registration is off outside dev
mode and the first admin is created from the command line.

Two things make the line urgent rather than cosmetic:

1. **Contributions are one-way.** Contributors sign off under the
   [DCO](../../../CONTRIBUTING.md#sign-off-dco); there is no CLA. Their code is
   licensed to the project under AGPL-3.0 only, so it can never be relicensed
   into a closed Team edition. Anything that should be Team must be written
   there from the start, not moved later.
2. **Fleet code is about to grow.** Correlation, intel and response work is
   queued. Without a line, each of those PRs re-opens the question of which
   edition it belongs to.

## Decision

### The line

| Capability | Lite (this repository, AGPL-3.0) | Team (private repository) |
|---|---|---|
| Devices | Several devices, one owner (a homelab has more than one host) | Fleets across many owners, sites and tenants |
| Users and access | One local admin created by CLI or first-run setup; no open self-registration; the existing `ADMIN` / `ANALYST` / `VIEWER` roles stay | Multi-tenant organisations, SSO (OIDC/SAML), tenant-scoped RBAC, organisation audit log |
| Network binding | `127.0.0.1` by default; LAN access is an explicit opt-in | A coordinator deployed on a server |
| Correlation | Across the owner's own devices | Cross-tenant correlation and aggregated intel |
| Threat intel | Bundled, keyless tier plus the user's own runtime keys (ADR 0004) | Same tiers, plus intel aggregated across tenants |
| Response | Manual checklist and dry-run suggestions | Approval workflows; live actions stay dry-run by default |
| Export | The event schema and HTTP API | Adds OCSF export for SIEM pipelines |

### Rules that keep the line

1. **Lite never depends on Team.** No code in this repository imports Team
   code, and Lite must build, install and pass its tests with no Team package
   present. Team code lives under the reserved Python namespace `lsadra_team`
   (and the reserved sub-package name `lsadra.team`) and the reserved npm scope
   `@lsadra/team`; none of them may exist in, or be imported by, this
   repository.
2. **Team depends on Lite only through public contracts.** Team integrates with
   a Lite core over the frozen event schema ([ADR 0006](0006-event-schema-v1-freeze.md))
   and the documented HTTP and WebSocket API. It does not import Lite's Python
   modules.
3. **Team code is written fresh.** Nothing contributed to this repository is
   copied into Team. A Team feature that resembles a Lite one is a new
   implementation against the contracts above.
4. **Nothing moves from Lite to Team.** A capability Lite ships stays in Lite.
   Team adds capabilities on top; it never takes them away from Lite users.
5. **Lite stays light and keyless.** A Team requirement never adds a server
   stack, a recurring cost or a mandatory API key to Lite.

### Enforcement

- [`scripts/check_tier_boundary.py`](../../../scripts/check_tier_boundary.py)
  scans every Python and frontend source file. It fails on a static import of
  `lsadra_team` or `lsadra.team`, on the same names passed to
  `importlib.import_module` or `__import__`, on an import of `@lsadra/team`, and
  on either reserved package path existing in this repository.
  [`tests/test_tier_boundary.py`](../../../tests/test_tier_boundary.py) runs it
  in CI on every pull request and proves it catches each of those forms.
- `ruff.toml` bans the same Python modules (rule `TID251`), so editors and the
  lint job flag a violation as it is written.
- The private Team repository carries the mirror rule (Team never imports
  `lsadra`) and its own check.

## Consequences

- The earlier planning assumption that Lite is a single device with no roles is
  superseded. Multi-device support for one owner and the existing roles are Lite
  features and stay AGPL.
- The private Team repository is created empty, holding only this boundary rule
  and its import check, so the line exists before any Team code is written.
- A PR that adds multi-tenancy, SSO, cross-tenant correlation, approval
  workflows or OCSF export to this repository is out of scope here and belongs
  in Team.
- Because Team talks to Lite only through the event schema and the API, changes
  to those contracts are now visible to two products. The schema's compatibility
  policy in [`docs/contracts/README.md`](../../contracts/README.md) already
  covers the event side; API changes should be called out in release notes.
- Renaming the reserved namespaces later requires a new ADR, because the Team
  repository and this check both depend on them.
