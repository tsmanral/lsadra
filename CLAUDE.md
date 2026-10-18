# Rules for AI coding agents

This file is read by Claude Code and similar agents working in this repository. It holds the
rules that keep agent work safe to merge. Human contributors follow the same process through
[CONTRIBUTING.md](CONTRIBUTING.md); this file states the parts an agent must never skip.

## Branches and merging

- `main` is protected. Every change lands through a pull request, opened from a feature branch.
  Never push to `main`.
- Never force-push a branch someone else created, never rewrite published history, and never
  delete or move a tag. On a branch you created, prefer a merge commit over a rebase once the
  PR is open.
- Open pull requests as drafts. Mark one ready for review only when CI is green.
- Merge only when the project lead has said so for that PR **and** the required checks (`dco`,
  `lint`, `test` on Ubuntu, Windows and macOS) are green on the current head. Never bypass
  branch protection, and never close and reopen a PR or push an empty commit to re-run CI.
- Releases are outward-facing: never push a `v*` tag unless the lead asked for that release.

## Before every commit

Run both gates and keep the output for the PR description. Never claim a change is done
without it.

```bash
python tests/test_v4_smoke.py        # every check must pass
python -m pytest tests/security/ -q  # 0 failures
ruff check .                         # lint, as in CI
```

When `frontend/` changes, also run `cd frontend && npm ci && npm run build`.

- If a gate fails on code you did not touch, stop and report it. Do not fix unrelated breakage
  silently inside your change.
- Never skip, disable, weaken or `xfail` a test to make a gate pass.

## Commits

- Conventional Commit subjects (`feat:`, `fix:`, `chore:`, ...), checked by commitlint.
- Sign off every commit (`git commit -s`). The `dco` check is required, so an unsigned commit
  blocks the merge.

## Security and private material

- Never commit secrets, tokens, webhook URLs or real log excerpts. Test and demo data stays
  clearly synthetic (`*.demo` users, RFC 5737 / RFC 3849 addresses).
- Some planning files and the local `.claude/` folder are gitignored on purpose. Never
  `git add -f` an ignored file, and never copy their contents into commits, issues, PRs or docs.
- Report vulnerabilities privately (see [SECURITY.md](SECURITY.md)). Never describe the location
  of an unfixed vulnerability in a commit, issue, PR or committed doc.
- A security fix ships with a regression test in `tests/security/` that fails on the old code.
- Changes that alter what the product does on a monitored host (blocking, killing, isolating)
  stay dry-run by default and require human approval for live actions.

## Stop and ask the lead first

- Anything outward-facing beyond a normal PR: force-push, tag deletion, repository settings,
  branch protection, publishing announcements, creating repositories.
- Evidence that contradicts a decision recorded in an ADR under `docs/architecture/adr/`.
- Any change to CI that removes or weakens a required check.

## Docs

Any PR that changes user-facing behavior, environment variables, API endpoints or project
structure updates `README.md` in the same PR.
