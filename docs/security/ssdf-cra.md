# Secure development (NIST SSDF) and the EU Cyber Resilience Act

This page maps what the project already does to the NIST Secure Software
Development Framework (SP 800-218, SSDF 1.1) and states the project's working
position on the EU Cyber Resilience Act (Regulation (EU) 2024/2847, "CRA").

> This is the maintainers' working position, written to guide engineering. It is
> not legal advice. Anyone selling or embedding LSADRA should take their own.

## SSDF practice map

| SSDF practice | What LSADRA does today | Where |
|---|---|---|
| **PO.1** Define security requirements | Security policy, supported versions and disclosure targets; threat model with trust boundaries | [SECURITY.md](https://github.com/tsmanral/lsadra/blob/main/SECURITY.md), [threat model](../threat-models/product-stride.md) |
| **PO.2** Roles and responsibilities | Single project lead approves merges and releases; rules for AI coding agents | `CLAUDE.md`, [CONTRIBUTING.md](https://github.com/tsmanral/lsadra/blob/main/CONTRIBUTING.md) |
| **PO.3** Supporting toolchains | CI on Ubuntu, Windows and macOS; ruff lint; GitHub Actions pinned to commit SHAs; Dependabot | `.github/workflows/`, `.github/dependabot.yml` |
| **PO.4** Security checks | Required checks (`dco`, `lint`, `test` on three OSes) gate every merge to `main` | Branch protection on `main` |
| **PO.5** Secure environments | `main` protected with no admin bypass; contributions only through pull requests | Branch protection |
| **PS.1** Protect code from tampering | Signed-off commits (DCO); protected branch; no force-push to shared branches | `dco.yml`, branch protection |
| **PS.2** Release integrity | Releases built by CI from a tag; container image published to GHCR by the release workflow | `release.yml` |
| **PS.3** Archive releases | Tagged releases with generated notes on GitHub | GitHub Releases |
| **PW.1** Design to meet requirements | Architecture decision records; threat model reviewed when boundaries change | `docs/architecture/adr/` |
| **PW.4** Reuse well-secured components | Small, mainstream dependency set; Dependabot updates | `requirements.txt` |
| **PW.5** Secure coding | Logs treated as attacker-controlled input; output sanitizer for narratives; parameterised SQL | `lsadra/explainability/sanitize.py` |
| **PW.7** Code review and analysis | Every change through a reviewed PR; AI-assisted security review before each release | [Release security review](release-security-review.md) |
| **PW.8** Test executable code | Smoke gate, security regression suite, storage contracts, parser fuzz tests | `tests/`, `tests/security/`, `tests/fuzz/` |
| **PW.9** Secure defaults | Fails closed outside dev mode when required secrets are missing; outbound enrichment opt-in | `lsadra/config.py` |
| **RV.1** Identify vulnerabilities | Private vulnerability reporting; gitleaks on every PR; weekly verified TruffleHog sweep | `security-scan.yml` |
| **RV.2** Assess and remediate | Acknowledge within 72 hours, triage within 7 days; every security fix ships with a regression test that fails on the old code | SECURITY.md, `tests/security/` |
| **RV.3** Root-cause analysis | Fixes add a regression test and, where the class recurs, a guard test across the codebase | `tests/security/` |

Known gaps against SSDF (signed and attested release images, an SBOM per
release, hash-locked dependencies) are tracked on the project roadmap.

## CRA position

### Key dates

- **11 September 2026.** Manufacturers' duty to report actively exploited
  vulnerabilities and severe incidents (Article 14) applies.
- **11 December 2027.** The remaining obligations apply, including the essential
  requirements in Annex I and conformity assessment.

### LSADRA Lite (free, open source)

LSADRA Lite is free and open-source software, developed in the open and not
monetised. The CRA does not apply to free and open-source software that is not
made available in the course of a commercial activity, so the project does not
treat Lite as a "product with digital elements placed on the market".

The CRA's lighter "open-source software steward" role (Article 24) applies to
legal persons that give sustained support to open-source software intended for
commercial use. LSADRA is maintained by an individual today, so that role does
not attach. If a company or foundation starts backing the project, it would take
on the steward duties:

- keep and document a cybersecurity policy that covers vulnerability handling
  and voluntary reporting (SECURITY.md and this page are the starting point);
- cooperate with market surveillance authorities on request;
- report actively exploited vulnerabilities and severe incidents, to the extent
  it takes part in development (Article 24(3) with Article 14).

Even without a legal duty, Lite follows the habits the CRA expects: a published
disclosure channel, fixed response targets, secure defaults, and security
updates for the latest release.

### LSADRA Team (planned paid edition)

A paid edition is commercial activity, so whoever sells it is the
**manufacturer** and takes on the full duties:

- **Annex I essential requirements:** secure by default, protection of data at
  rest and in transit, minimal attack surface, logging of security-relevant
  events, and security updates for the declared support period.
- **Vulnerability handling (Annex I, Part II):** an SBOM for each release, a
  coordinated disclosure policy, and security fixes shipped without delay and
  free of charge.
- **Reporting (Article 14):** an early warning to the national CSIRT and ENISA
  within 24 hours of becoming aware of an actively exploited vulnerability or a
  severe incident, a fuller notification within 72 hours, and a final report
  afterwards.
- **Classification:** security information and event management systems are
  listed as "important" products (Annex III, Class I). Conformity can be
  self-assessed only against harmonised standards or certification schemes;
  otherwise a notified body is needed.
- **Support period:** declared up front, normally at least five years.

The engineering items that Team needs before sale (signed releases with an SBOM,
an audit trail, and an incident-reporting procedure) are on the roadmap.
