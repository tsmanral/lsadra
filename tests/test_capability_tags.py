"""Guard: source comments use neutral capability tags.

Older code carried vendor-programme names as alignment tags. They described no
real integration and implied an affiliation, so they were replaced with
``[Capability: ...]`` tags (gap G-25). This test keeps them from coming back.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RETIRED = re.compile(r"\b(MYTHOS|GLASSWING)\s+ALIGNMENT\b", re.IGNORECASE)


def test_no_retired_alignment_tags_in_python_sources():
    offenders = []
    for path in (ROOT / "lsadra").rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if RETIRED.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}")
    assert not offenders, "retired alignment tags found: " + ", ".join(offenders)
