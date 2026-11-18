#!/usr/bin/env python3
"""Ratchet for ruff's security (flake8-bandit, ``S``) rules.

The codebase predates these rules, so they are not in ruff.toml's ``select``
yet. Instead this script counts findings per rule and fails when any rule has
more findings than the recorded baseline. New code cannot add findings;
fixing old ones lowers the count, and ``--update`` writes the new, lower
baseline so the gain is kept.

    python scripts/ruff_security_ratchet.py           # check (CI)
    python scripts/ruff_security_ratchet.py --update  # after fixing findings

Run with the ruff version pinned in requirements/ci-tools.txt; another
version may count differently.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / ".github" / "ruff-security-baseline.json"


def current_counts() -> Counter[str]:
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["ruff", "check", ".", "--select", "S", "--output-format", "json", "--exit-zero"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return Counter(item["code"] for item in json.loads(proc.stdout))


def main(argv: list[str]) -> int:
    counts = current_counts()
    if "--update" in argv:
        BASELINE.write_text(json.dumps(dict(sorted(counts.items())), indent=2) + "\n")
        print(f"baseline written: {sum(counts.values())} findings")
        return 0

    baseline: dict[str, int] = json.loads(BASELINE.read_text())
    worse = {code: (baseline.get(code, 0), n) for code, n in counts.items() if n > baseline.get(code, 0)}
    better = {code: (b, counts.get(code, 0)) for code, b in baseline.items() if counts.get(code, 0) < b}

    print(f"ruff S findings: {sum(counts.values())} (baseline {sum(baseline.values())})")
    for code, (b, n) in sorted(better.items()):
        print(f"  {code}: {b} -> {n} (improved; run with --update to lock it in)")
    if worse:
        for code, (b, n) in sorted(worse.items()):
            print(f"::error::ruff {code}: {n} findings, baseline allows {b}")
        print("Fix the new findings (ruff check --select S .) rather than raising the baseline.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
