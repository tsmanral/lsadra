# Contributing

See the repository [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full guide
(dev setup, project map, PR process, AI-assisted-development policy).

Quick notes:

- **Conventional Commits** are enforced (commitlint).
- **Sign off** every commit — `git commit -s` (DCO).
- Run the gates before pushing: `python tests/test_v4_smoke.py` and
  `python -m pytest tests/security/`.
- Never commit secrets, credentials, or real log excerpts.
