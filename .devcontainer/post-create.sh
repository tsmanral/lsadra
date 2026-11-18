#!/usr/bin/env bash
# Installs everything a contributor needs; runs once when the container is created.
set -euo pipefail
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt 2>/dev/null \
  || pip install -r requirements.txt pytest ruff pre-commit
(cd frontend && npm ci --no-audit --no-fund)
python tests/test_v4_smoke.py
cat <<'MSG'

LSADRA dev container is ready.
  API:        python -m uvicorn server:app --host 0.0.0.0 --port 8000
  Demo data:  python scripts/seed_demo.py      (login: demo.admin / demo-only-not-a-secret)
  Dashboard:  cd frontend && npm run dev -- --host
  Tests:      python -m pytest tests/ -q
MSG
