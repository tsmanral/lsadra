# Release security review

Before every release tag, the maintainer runs an AI-assisted security review of
the code that changed since the last release, then checks each finding by hand.
Large vendors now run the same practice on their own code with frontier models;
for a small project it is the cheapest way to get a second pair of eyes on every
release.

The review is a maintainer task. It runs locally or in a private session, and
its raw output never goes into a public issue, PR or commit.

## Steps

1. **Pick the range.** Everything between the previous tag and the release
   candidate: `git diff <previous-tag>..HEAD`.
2. **Run the review.** Use an AI code reviewer with security focus over that
   diff (for example Claude Code's `/security-review`). Point it at the threat
   model so it knows the trust boundaries:
   [product threat model](../threat-models/product-stride.md).
3. **Reproduce every finding.** A finding counts only if you can show it: a
   failing test, a request that returns data it should not, a crash. Drop the
   ones you cannot reproduce and note why.
4. **Track privately.** Confirmed findings go into a private security advisory,
   as described in [SECURITY.md](../../SECURITY.md). Never describe the location
   of an unfixed issue anywhere public.
5. **Fix with a test.** Each fix ships with a regression test in
   `tests/security/` that fails on the old code.
6. **Update the threat model** if the review found a boundary or input the model
   did not cover.
7. **Record the result** in the release notes in one line, without details, for
   example "Pre-release security review: 2 findings fixed, 0 open."

## Release gate

Do not push a release tag while a confirmed finding of high or critical severity
is open, unless the release itself contains the fix.
