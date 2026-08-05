# 0005. Apple testing strategy — Apple-less local dev, Apple-covered CI

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** project lead
- **Supersedes in part:** [ADR 0003 — Apple-less development strategy](0003-apple-less-strategy.md)

## Context

[ADR 0003](0003-apple-less-strategy.md) recorded a blanket "Apple-less" position: no
Mac or iPhone hardware, no paid Apple Developer Program membership, and therefore
no Apple-dependent work. That was the right call for *local development*, and
nothing here changes it.

But "Apple-less" has been read more broadly than it should be — as if Apple
platforms cannot be **tested** at all. That is not true, and the gap matters
because the project's Apple-facing surface is growing:

- macOS is already in the CI test matrix.
- A Rust collector for macOS is planned as a community beta (M2).
- A Tauri v2 desktop app is planned (M3).
- A PWA companion is the entire iOS story (M4) — iOS users get no native app,
  so Mobile Safari behavior *is* the product on that platform.
- The SPA framework is now decided as React, which makes React Native a
  plausible — not committed — future mobile path.

Two constraints are unchanged and bind everything below: **zero recurring cost**
and **no Apple hardware**. This ADR asks a narrower question than ADR 0003 did:
*given those constraints, how much Apple test coverage can the project actually
get, and where is the genuine wall?*

## Decision

Amend the ADR 0003 position from **"Apple-less"** to **"Apple-less local
development, Apple-covered CI and testing."**

Concretely:

1. **GitHub-hosted macOS runners are the normative Apple testing substrate.**
   They are free and unlimited for public repositories, require no account, no
   vendor relationship, and no approval. Every Apple capability the project
   commits to must be reachable from a standard macOS runner.

2. **No third-party device cloud becomes a hard dependency.** Free OSS tiers from
   commercial vendors are discretionary grants that can be revoked or re-scoped.
   They may supplement CI; they may never gate it.

3. **The paid Apple Developer Program ($99/yr) stays refused**, and the
   capabilities behind it are recorded below as *permanent, accepted gaps* — not
   as deferred work. Calling them "deferred" implies a plan to close them; there
   is none.

4. **React Native / EAS is explicitly not adopted** as the mobile path. The PWA
   remains the iOS story.

### Option assessment

| Option | Cost | What it genuinely covers | Verdict |
|---|---|---|---|
| **GitHub Actions macOS runners** | $0, unlimited on public repos | Backend pytest on macOS; Rust collector compile/test; unsigned + ad-hoc Tauri bundles; Playwright WebKit; iOS Simulator + Mobile Safari; Appium/XCUITest against the Simulator | **Adopt.** The backbone. |
| **TestingBot OSS program** | $0 ("free forever", 2 concurrent, real iOS devices) | Real-device iOS Safari, automated | Supplement, apply at M4 |
| **BrowserStack OSS program** | $0 (lifetime, 5 parallels) | Real-device iOS Safari, **interactive** — best for manual PWA-install checks | Supplement, apply at M4 |
| **Appetize.io free tier** | $0 — 30 min/month, 3-minute sessions | Streamed iOS Simulator in a browser | Reject for testing; possible "try it in your browser" demo link |
| **LambdaTest / Sauce Labs OSS** | $0, terms unclear | Similar grids | Reject — LambdaTest's published criteria include a geographic qualifier; Sauce Labs publishes no OSS terms |
| **Expo / EAS cloud builds** | $0 for 15 iOS builds/month | Builds an iOS app without a Mac — but only *simulator* artifacts without a paid account | Reject as strategy; see below |
| **Local Xcode / Simulator tooling** | Requires a Mac | — | Not applicable. No hardware. |

### Why Expo/EAS is rejected despite being free

EAS will build an iOS Simulator `.app` with no Apple Developer account — that part
is real. The wall is downstream: installing a signed build on a *physical iPhone*
requires ad-hoc or enterprise provisioning, and both require the paid program.
Adopting React Native/EAS would mean buying a build pipeline whose output cannot
be installed on the target device. The binding constraint is Apple's provisioning
model, not Expo's pricing, so no vendor choice moves it.

The PWA path is the only one in the assessment that requires **no Apple account at
any stage** — build, simulator, real device, or distribution. That is why it wins.

Choosing React (D5) keeps the React Native door open at near-zero switching cost
if the $99/yr constraint is ever lifted. This ADR does not close that door; it
declines to walk through it now.

## Workflow changes this implies

Each is additive and none requires a secret:

- **M2 — macOS Rust collector job.** Rust is preinstalled on the runners; no
  signing needed. This is the load-bearing change: it converts "macOS collector is
  a CI-built beta" from an assertion into something verified on every push.
- **M3 — Tauri macOS bundle job.** Build unsigned, or ad-hoc signed with
  `signingIdentity: "-"`, and launch-smoke it on the same runner. Artifact-only,
  non-blocking at first.
  > Trap worth recording: Tauri's bundler skips signing cleanly when no identity
  > is configured, but setting `APPLE_ID`/`APPLE_PASSWORD` *without*
  > `APPLE_TEAM_ID` is a hard build failure. Set none of them.
- **M4 — PWA lane.** Playwright WebKit on macOS, plus an iOS Simulator Mobile
  Safari smoke job. Gate on service-worker registration, manifest parse, and
  offline cache behavior — **not** on web push or Add-to-Home-Screen, which are
  unreliable to automate.
- **M5 — no change.** This ADR does not unblock signed macOS distribution.

Practical notes for whoever writes these: pin `macos-15` or `macos-26` rather than
`macos-latest` (`macos-14` is deprecated, and `macos-26` dropped the iOS 18.x
simulator runtimes); never use `-large`/`-xlarge` labels, which are billed even on
public repos; resolve simulator runtimes at job time instead of hardcoding a
device name; and budget for 14 GB of runner disk already partly consumed by
several Xcode installs.

## Consequences

**Gained**

- macOS stops being a platform the project merely claims to support and becomes
  one it verifies, at no cost.
- The iOS PWA gets real Mobile Safari coverage before users find the bugs.
- The zero-cost constraint is preserved with no new accounts, secrets, or vendor
  relationships on the critical path.

**Accepted permanent gaps** (all require the paid membership; none has a free
substitute)

- **Notarization and Developer ID signing.** macOS downloads will trip Gatekeeper.
  Distribution stays source/Homebrew with a documented caveat.
  > Update needed elsewhere: macOS 15 Sequoia removed the Control-click → Open
  > override, so the documented workaround must now be
  > `xattr -dr com.apple.quarantine <app>`, not "right-click and choose Open."
  > Existing docs that say otherwise are stale.
- **Real-device iOS and macOS testing**, TestFlight, and provisioning-gated
  entitlements.
- **iOS web push end-to-end**, which requires a Home Screen install and a direct
  user gesture — not automatable in CI.
- **Real Safari WebDriver** is fragile in CI (it needs GUI-level authorization);
  Playwright's WebKit build is the practical substitute, and it is the engine, not
  the branded browser.

**Costs**

- More CI jobs to maintain, and macOS jobs are capped at 5 concurrent.
- Simulator boot is a known flakiness source; jobs need `bootstatus` gating and a
  retry rather than a bare `boot`.
- **This is all conditional on the repository staying public.** Going private
  turns macOS minutes into billed time at roughly ten times the Linux rate, which
  would break the zero-cost constraint. That dependency should be explicit.

## Status of the underlying decision

**Accepted 2026-08-06.** The project lead signed the amended D4 position:
Apple-less local development, Apple-covered CI and testing. ADR 0003 is
superseded in part by this record — its local-development stance stands, its
implied "no Apple testing" reading does not.

## Notes on evidence

Runner specifications, pricing, free-tier terms, and Apple membership boundaries
were checked on **2026-08-05** against vendor and Apple documentation. Vendor free
tiers and OSS-program terms change without notice, and BrowserStack's and Sauce
Labs' OSS eligibility criteria are not published — the recommendation to treat
device clouds as non-gating supplements exists partly for that reason. The
capability claims about iOS Simulator automation without an Apple ID reflect
standard CI practice rather than an explicit Apple guarantee, and should be
confirmed by a single spike job before M4 depends on them.
