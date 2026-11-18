"""The product is called LSADRA (ADR 0002). Earlier names must not reach users.

"Glass Sentinel" stayed on the login page and in the automation console after the
rename, and "AI-Sentinel" headed the exported executive report. This scans the
user-facing sources so a leftover or a copied-in old name fails CI.

Internal storage keys such as ``sentinel_token`` are not user-facing and are left
alone on purpose: renaming them would sign every user out and drop saved state.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

OLD_NAMES = re.compile(
    r"glass[\s_-]*sentinel|ai[\s_-]sentinel|sentinel_cmd|sentinel-agent|sentinel-server",
    re.IGNORECASE,
)

SCANNED = [
    (REPO_ROOT / "frontend" / "src", ("*.ts", "*.tsx", "*.css")),
    (REPO_ROOT / "frontend", ("index.html",)),
    (REPO_ROOT / "frontend" / "public", ("*.svg",)),
    (REPO_ROOT / "lsadra", ("*.py", "*.sh", "*.ps1")),
    (REPO_ROOT, ("server.py", "README.md")),
]


def _files():
    for base, patterns in SCANNED:
        for pattern in patterns:
            yield from base.rglob(pattern) if base != REPO_ROOT else base.glob(pattern)


def test_no_old_product_name_in_user_facing_sources():
    hits = []
    for path in _files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), 1):
            if OLD_NAMES.search(line):
                hits.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()[:100]}")
    assert not hits, "Old product name found; use LSADRA (ADR 0002):\n" + "\n".join(hits)


def test_scan_covers_the_login_page():
    assert any(p.name == "Login.tsx" for p in _files())
