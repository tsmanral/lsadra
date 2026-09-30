"""Pytest configuration for the LSADRA test suite.

Imported by pytest before any test module, so it runs before `lsadra.config`
is first imported. Selecting dev mode here keeps the production boot guards
(§6 #4 JWT secret, §6 #6 TLS) from tripping during tests, without weakening the
guards themselves (they are exercised in dedicated subprocess tests).
"""

import os

os.environ.setdefault("LSADRA_DEV_MODE", "true")

# test_v4_smoke.py is a standalone script (`python tests/test_v4_smoke.py`) that
# exits at import time; keep a bare `pytest` from crashing while collecting it.
collect_ignore = ["test_v4_smoke.py"]
