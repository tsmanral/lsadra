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
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY requirements/ /tmp/requirements/
# Every file pip downloads must match a hash in the lock (--require-hashes).
RUN pip install --require-hashes \
      -r /tmp/requirements/base.txt \
      -r /tmp/requirements/ml.txt \
      -r /tmp/requirements/ui.txt \
 && pip check

# ── Stage 2: runtime ───────────────────────────────────────────────────────
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime

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

# Python, not curl: the slim runtime ships no curl. Probes plain HTTP, then the
# launcher's TLS listener (self-signed by default, so not verified on loopback).
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "scripts/container_healthcheck.py"]

# Default: run the API server through the launcher, which applies the listener
# policy (G-8): plain HTTP beyond loopback only with TLS configured, a trusted
# proxy, or LSADRA_ALLOW_PLAINTEXT_LISTENER (docker-compose.yml sets it and
# publishes the port on the host's loopback only).
ENV LSADRA_API_HOST=0.0.0.0
CMD ["python", "-m", "lsadra.serve"]
