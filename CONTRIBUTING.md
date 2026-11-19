# Contributing to LSADRA

Thank you for your interest in contributing to LSADRA (Local Security Anomaly Detection & Risk Assessment)! This project thrives on community contributions — code, detection rules, documentation, and bug reports are all welcome.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Sign-off (DCO)](#sign-off-dco)
- [Pull Request Process](#pull-request-process)
- [AI-Assisted Development](#ai-assisted-development)
- [Coding Standards](#coding-standards)
- [Adding Detection Rules](#adding-detection-rules)
- [Adding Log Parsers](#adding-log-parsers)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)
- [Security Issues](#security-issues)
- [Code of Conduct](#code-of-conduct)

## Architecture Overview

LSADRA is an explainable SIEM platform: a **FastAPI** backend with a multi-layer ML detection pipeline, a **React (Vite + TypeScript)** SOC dashboard, and lightweight endpoint agents.

### Key Technologies

| Technology | Purpose |
|---|---|
| **Python 3.12 / FastAPI** | Ingestion API, auth (JWT + RBAC), detection orchestration |
| **scikit-learn** | Ensemble anomaly models (Isolation Forest, LOF, One-Class SVM) + MLP autoencoder |
| **SHAP** | Per-alert feature attribution and explainability |
| **SQLite** | Zero-dependency persistence (events, incidents, models, feedback) |
| **APScheduler** | Background jobs: correlation, drift detection, threat-intel caching, retention |
| **React + Vite + TypeScript** | SOC dashboard (live threat feed, investigation, tuning) |
| **Docker Compose** | Production deployment |

### Directory Structure

| Directory | Purpose |
|---|---|
| `lsadra/ingestion/` | Multi-source log parsers (Syslog, Windows Events, NetFlow, endpoint) + ingestion API |
| `lsadra/detection/` | Rule engine, ML ensemble, severity scoring, lateral-movement detection |
| `lsadra/explainability/` | SHAP attribution, MITRE ATT&CK mapping, narrative builder |
| `lsadra/storage/` | Database layer + SQL migrations |
| `lsadra/scheduler/` | Background job definitions |
| `lsadra/endpoint_agent/` | Linux agent (auth.log / journalctl auto-detection) |
| `lsadra/ui/` | Legacy Streamlit dashboard + dashboard data layer |
| `frontend/` | React SOC dashboard |
| `tests/` | Test suite + end-to-end smoke tests |
| `datasets/` | Synthetic log generators for local experimentation |

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/lsadra.git
   cd lsadra
   ```
3. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/my-improvement
   ```

`main` is the only long-lived branch — all work lands through short-lived feature branches and pull requests.

## Development Setup

**Fastest start:** open the repository in a dev container (VS Code "Reopen in Container", or GitHub
Codespaces opened in VS Code). [`.devcontainer/`](.devcontainer/) installs Python 3.12, Node 24 and
every dependency, sets local dev mode, runs the smoke test, and prints the commands to start the API
and dashboard. The dashboard calls the API at `http://localhost:8000`, so in a browser-only Codespace
it can't reach the API yet; use VS Code desktop, which forwards `localhost`. The manual setup below
works everywhere.

You need **Python 3.12+**, **Node.js 22+** (CI uses Node 24) and **git**. Commands below use the
Windows venv layout (`venv/Scripts/...`); on Linux/macOS use `venv/bin/...` instead.

### Backend

```bash
py -3.12 -m venv venv                          # Linux/macOS: python3.12 -m venv venv
venv/Scripts/pip install -r requirements.txt -r requirements-dev.txt
```

Every package is pinned and hash-checked; see [requirements/README.md](requirements/README.md).

Start the API in **local dev mode**. Outside dev mode the server refuses to start without a
`LSADRA_JWT_SECRET` and TLS, which is what you want in production and not what you want on your
laptop. `LSADRA_CORS_ORIGINS` lets the dashboard on port 5173 call the API.

```bash
# bash / zsh
export LSADRA_DEV_MODE=true LSADRA_CORS_ORIGINS=http://localhost:5173
venv/bin/python -m uvicorn server:app --host 127.0.0.1 --port 8000
```

```powershell
# PowerShell
$env:LSADRA_DEV_MODE="true"; $env:LSADRA_CORS_ORIGINS="http://localhost:5173"
venv/Scripts/python -m uvicorn server:app --host 127.0.0.1 --port 8000
```

`http://127.0.0.1:8000/api/health` should answer `{"status":"ok", ...}` and the API docs are at
`http://127.0.0.1:8000/docs`. Every other variable is documented in [`.env.example`](.env.example).

### Demo data

With the API running, replay the labeled synthetic corpus through the real ingestion API:

```bash
venv/Scripts/python scripts/seed_demo.py
```

It registers the dashboard user `demo.admin` (password `demo-only-not-a-secret`) and a
`demo-host-01` device, then sends about 200 events that trigger alerts. Log in to the dashboard
with that user. The data is synthetic by construction; never point the seeder at a real deployment.

### Frontend

```bash
cd frontend
npm ci             # exact versions from package-lock.json
npm run dev        # dashboard at http://localhost:5173, talks to the API on :8000
```

The API address is set in `frontend/src/services/api.ts`. See [frontend/README.md](frontend/README.md).

### Running the checks

These are the same checks CI runs. Run the ones that match what you changed:

| You changed | Run | Takes about |
|---|---|---|
| Anything in Python | `venv/Scripts/python tests/test_v4_smoke.py` (expect 27/27) | 5 s |
| Anything in Python | `venv/Scripts/python -m pytest tests/security/ -q` (0 failures) | 15 s |
| Anything in Python | `venv/Scripts/ruff check .` | 1 s |
| Parsers, detection, storage, API | `venv/Scripts/python -m pytest tests/ -q` (full suite) | 1-2 min |
| One area only | `venv/Scripts/python -m pytest tests/storage -q`, `tests/test_detection_pipeline.py`, ... | seconds |
| `frontend/` | `cd frontend && npx tsc -b --noEmit && npm run build && npm test && npx eslint .` | 30 s |

The frontend ESLint check in CI fails when the error count goes **above** a recorded baseline
(lint debt is being paid down file by file). If your PR lowers the count, lower the baseline in
`.github/workflows/ci.yml` too.

Optional but handy: `pre-commit install && pre-commit install --hook-type commit-msg` runs lint,
secret scanning and the Conventional Commit check before each commit.

### Your first pull request, start to finish

```bash
git checkout -b fix/short-description
# ... make the change, add or update a test ...
venv/Scripts/python tests/test_v4_smoke.py && venv/Scripts/python -m pytest tests/security/ -q
venv/Scripts/ruff check .
git commit -s -m "fix(parsers): handle empty syslog lines"
git push -u origin fix/short-description
```

Then open a pull request against `main`. The template asks what changed, why, and what you ran.
On a first PR from a fork, GitHub may hold the CI run until a maintainer approves it, so a short
wait before the checks appear is normal.

## How to Contribute

- **Good first contributions**: documentation fixes, new detection rules, new log parsers, test coverage, dashboard polish
- **Larger changes**: open an issue first describing what you want to build so we can align on the approach before you invest time
- **Not sure where to start?** Look for issues labelled [`good first issue`](../../labels/good%20first%20issue) or [`help wanted`](../../labels/help%20wanted), or browse the [issue tracker](../../issues)
- **Labels** live in [`.github/labels.json`](.github/labels.json) and are synced to the repository when that file changes on `main`; edit the file rather than the labels page

## Sign-off (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) — **there is no CLA**. You keep the copyright to your contribution; you are simply certifying that you have the right to submit it under the project's AGPL-3.0 license.

Sign off every commit by adding `-s`:

```bash
git commit -s -m "feat(detection): add DNS tunneling rule"
```

That appends a line to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email must match your git `user.name` and `user.email`. Set them once with:

```bash
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

**This is enforced, not advisory.** The DCO check is a *required status check* on `main`, so a PR containing an unsigned commit cannot be merged until it is fixed. If you forget:

```bash
git commit --amend -s --no-edit                 # last commit only
git rebase --signoff main                       # every commit on your branch
git push --force-with-lease                     # then update the PR
```

## Pull Request Process

1. Keep PRs focused — one logical change per PR
2. Follow the existing commit style: `type(scope): description` (e.g. `feat(detection): add DNS tunneling rule`, `fix(api): scope export to requesting user`). CI checks every commit message with commitlint (`commitlint.config.js`)
3. **Sign off every commit** (`git commit -s`) — see [Sign-off (DCO)](#sign-off-dco). This is a required check; an unsigned commit blocks the merge.
4. Run the smoke test and any tests relevant to your change
5. Update documentation if your change affects setup or architecture. Changes to user-facing behavior, environment variables, endpoints, or project structure must update `README.md` **in the same PR**
6. Open the PR against `main` with a clear description of **what** changed and **why**
7. A maintainer will review your PR — please be responsive to feedback

Every PR runs the full CI matrix (Ubuntu, Windows, macOS), a lint pass, secret scanning, and the DCO check. `main` is protected — all work lands through pull requests, maintainer changes included.

## AI-Assisted Development

AI-assisted contributions (Copilot, Claude, ChatGPT, etc.) are welcome — much of this project is built with AI assistance. However:

- **You are responsible for your contribution.** Review, understand, and test everything you submit
- Do not submit unreviewed AI output — PRs that don't build or clearly weren't tested will be closed
- Security-sensitive code (auth, parsers, agent install paths) gets extra scrutiny regardless of how it was written
- Autonomous coding agents follow [CLAUDE.md](CLAUDE.md): PR-only, no force-push, gates before every commit, and merges only on the maintainer's word

## Coding Standards

### Python

- Follow PEP 8; keep functions small and focused
- Use type hints on public function signatures
- No hardcoded secrets, keys, or credentials — ever (CI and review will check)
- Parsers must never trust input: log ingestion is an attack surface

### TypeScript / React

- Strict TypeScript — avoid `any` where practical
- Keep API calls in `frontend/src/services/`, not inside components
- Authentication and authorization logic belongs server-side only

## Adding Detection Rules

Detection rules live in the V4 rule engine (`lsadra/detection/`). A good rule PR includes:

1. The rule implementation with tunable thresholds (no magic numbers)
2. A severity contribution that fits the existing additive scoring model
3. A narrative template so alerts remain human-readable
4. Test cases with sample log lines that should (and should not) trigger it

## Adding Log Parsers

Parsers live in `lsadra/ingestion/`. New parsers should:

1. Extend the base parser interface
2. Handle malformed input gracefully (never crash the pipeline on a bad line)
3. Emit the normalized event schema used by the feature extractor
4. Include fixture-based tests with real-world sample lines

## Reporting Bugs

Open an issue with the **Bug report** form, which asks for:

- What you expected vs. what happened
- Steps to reproduce (sample log lines are gold)
- Environment: OS, Python version, how you deployed (local / Docker)
- Relevant logs (redact anything sensitive!)

## Feature Requests

Open an issue with the **Feature request** form, describing the problem you're trying to solve (not just the solution). Detection gaps, missing log sources, and dashboard workflow pain points are especially valuable feedback.

## Security Issues

**Never report vulnerabilities in public issues.** See our [Security Policy](SECURITY.md) for private reporting channels. The issue chooser links straight to private vulnerability reporting.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## License

By contributing, you agree that your contributions will be licensed under the [GNU AGPL v3.0](LICENSE), the same license that covers the project.
