"""Pytest configuration for the LSADRA test suite.

Imported by pytest before any test module, so it runs before `lsadra.config`
is first imported. Selecting dev mode here keeps the production boot guards
(§6 #4 JWT secret, §6 #6 TLS) from tripping during tests, without weakening the
guards themselves (they are exercised in dedicated subprocess tests).
"""

import os
import sys

import pytest

os.environ.setdefault("LSADRA_DEV_MODE", "true")

# test_v4_smoke.py is a standalone script (`python tests/test_v4_smoke.py`) that
# exits at import time; keep a bare `pytest` from crashing while collecting it.
collect_ignore = ["test_v4_smoke.py"]


@pytest.fixture(autouse=True)
def _reset_detection_queue():
    """Ingestion enqueues onto a process-wide detection queue that only a
    running lifespan drains; TestClient(app) without ``with`` never drains it,
    so reset it between tests to keep its bound from leaking across them."""
    yield
    worker = sys.modules.get("lsadra.detection.detection_worker")
    if worker is not None and not worker.detection_queue.running:
        worker.detection_queue.reset()
