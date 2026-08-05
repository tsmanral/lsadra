## What & why

<!-- One or two sentences: what this changes and the motivation. Link issues. -->

## Changes

<!-- Bullet the notable changes. Call out anything behavioral or breaking. -->

## Testing

<!-- Commands run and results. Security/parser changes: show the gate output. -->

```
python tests/test_v4_smoke.py      # expect 27/27
python -m pytest tests/security/    # expect 0 failures
```

## Checklist

- [ ] Conventional Commit messages
- [ ] `Signed-off-by` on every commit (`git commit -s`) — DCO
- [ ] Tests added/updated; gates green
- [ ] No secrets, credentials, or real log excerpts in code, tests, or docs
- [ ] Docs / `.env.example` updated if config or behavior changed
- [ ] **README/docs impact considered** — if this PR changes user-facing behavior, environment variables, endpoints, or project structure, `README.md` (and any affected doc) is updated *in this PR*. Tick with "n/a" if none apply.
