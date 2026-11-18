# syntax=docker/dockerfile:1
# LSADRA container image.
#
# Two stages: "builder" installs the hash-locked dependencies into a virtualenv
# (compilers and pip caches stay there), and "runtime" copies only that
# virtualenv and the app code. The runtime runs as an unprivileged user
# (uid/gid 10001) that can write only /app/data and /app/logs.
#
# The base image is pinned by digest; Dependabot (docker ecosystem) bumps it.

# ── Stage 1: dependencies ──────────────────────────────────────────────────
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY requirements/ /tmp/requirements/
# Every file pip downloads must match a hash in the lock (--require-hashes).
# torch.txt points pip at the PyTorch CPU index only, so it runs as a second
# install with --no-deps (its dependencies are locked in ml.txt).
RUN pip install --require-hashes \
      -r /tmp/requirements/base.txt \
      -r /tmp/requirements/ml.txt \
      -r /tmp/requirements/ui.txt \
 && pip install --require-hashes --no-deps -r /tmp/requirements/torch.txt \
 && pip check

# ── Stage 2: runtime ───────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

RUN groupadd --system --gid 10001 lsadra \
 && useradd --system --uid 10001 --gid 10001 --home-dir /app \
      --no-create-home --shell /usr/sbin/nologin lsadra

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
# App code stays owned by root, so the service user cannot modify it.
COPY . .
RUN mkdir -p /app/data/models /app/logs \
 && chown -R 10001:10001 /app/data /app/logs

USER 10001:10001

# API + legacy Streamlit dashboard
EXPOSE 8000 8501

# Python, not curl: the slim runtime ships no curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"]

# Default: run the API server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
