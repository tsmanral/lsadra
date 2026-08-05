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
| **scikit-learn / PyTorch** | Ensemble anomaly models (Isolation Forest, LOF, One-Class SVM) + autoencoder |
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

### Backend (Python 3.12 required)

```bash
py -3.12 -m venv venv                          # Linux/macOS: python3.12 -m venv venv
venv/Scripts/pip install -r requirements.txt   # Linux/macOS: venv/bin/pip
venv/Scripts/python -m uvicorn server:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev        # dashboard at http://localhost:5173
```

### Running Tests

```bash
venv/Scripts/python -m pytest tests/           # unit + integration tests
venv/Scripts/python tests/test_v4_smoke.py     # end-to-end smoke test (expected: 27/27)
```

Please make sure the smoke test passes before opening a PR.

## How to Contribute

- **Good first contributions**: documentation fixes, new detection rules, new log parsers, test coverage, dashboard polish
- **Larger changes**: open an issue first describing what you want to build so we can align on the approach before you invest time
- **Not sure where to start?** Check the [issue tracker](../../issues) for open items

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

**CI checks this on every PR.** An unsigned commit fails the DCO check, and maintainers will not merge a PR with a failing sign-off. If you forget:

```bash
git commit --amend -s --no-edit                 # last commit only
git rebase --signoff main                       # every commit on your branch
git push --force-with-lease                     # then update the PR
```

## Pull Request Process

1. Keep PRs focused — one logical change per PR
2. Follow the existing commit style: `type(scope): description` (e.g. `feat(detection): add DNS tunneling rule`, `fix(api): scope export to requesting user`)
3. **Sign off every commit** (`git commit -s`) — see [Sign-off (DCO)](#sign-off-dco). CI checks this on every PR.
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

Open an issue with:

- What you expected vs. what happened
- Steps to reproduce (sample log lines are gold)
- Environment: OS, Python version, how you deployed (local / Docker)
- Relevant logs (redact anything sensitive!)

## Feature Requests

Open an issue describing the problem you're trying to solve (not just the solution). Detection gaps, missing log sources, and dashboard workflow pain points are especially valuable feedback.

## Security Issues

**Never report vulnerabilities in public issues.** See our [Security Policy](SECURITY.md) for private reporting channels.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## License

By contributing, you agree that your contributions will be licensed under the [GNU AGPL v3.0](LICENSE), the same license that covers the project.
