# 0003. Apple-less development strategy

- **Status:** Accepted — **superseded in part by
  [ADR 0005](0005-apple-testing-strategy.md)** (2026-08-06)
- **Date:** 2026-07-24
- **Deciders:** project lead

> **Read this first.** The local-development stance below stands unchanged: no
> Mac, no iPhone, no paid Apple Developer membership, no Apple-dependent daily
> work. What ADR 0005 corrects is the *scope* — "Apple-less" was being read as
> "Apple platforms cannot be tested," which is false. GitHub-hosted macOS runners
> are free and unlimited on public repos and cover substantially more than the
> "CI-built beta only" line below implies. See
> [ADR 0005](0005-apple-testing-strategy.md) for what is actually covered, what
> the permanent gaps are, and why React Native/EAS was rejected.

## Context

No Mac or iPhone hardware is available to the maintainer, and acquiring Apple
hardware / paid developer-program membership conflicts with the
zero-recurring-cost constraint. macOS endpoint coverage still has real user value.

## Decision

- **No Apple-dependent development** — no local macOS/iOS builds and no reliance
  on Apple-only toolchains in day-to-day work.
- **macOS artifacts are CI-built beta only**, produced on GitHub-hosted macOS
  runners (free for public repos) and shipped clearly labeled beta/unsigned until
  a signing path exists.
- **Windows and Linux are first-class** supported platforms.

## Consequences

- The test matrix includes `macos-latest` so macOS stays buildable/testable
  without local Apple hardware.
- macOS code signing / notarization is deferred; users get a documented
  Gatekeeper caveat until then.
- Any feature that would require Apple hardware to develop or verify is out of
  scope until that constraint changes.
