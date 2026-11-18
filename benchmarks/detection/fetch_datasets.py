#!/usr/bin/env python3
"""
Download the pinned public dataset subsets listed in ``datasets.json``.

Files land in ``benchmarks/detection/.cache/`` (gitignored) and are checked
against the pinned sha256 before use. Nothing downloaded here is ever committed:
splunk/attack_data is Apache-2.0, but EVTX-ATTACK-SAMPLES is GPL-3.0 and is
used for testing only, never bundled.

    python benchmarks/detection/fetch_datasets.py            # all sources
    python benchmarks/detection/fetch_datasets.py --source splunk_attack_data
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "datasets.json"
DEFAULT_CACHE = HERE / ".cache"


def load_manifest() -> Dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def cache_path(cache_dir: Path, entry: Dict[str, Any]) -> Path:
    return cache_dir / entry["source"] / entry["path"]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def is_cached(cache_dir: Path, entry: Dict[str, Any]) -> bool:
    p = cache_path(cache_dir, entry)
    return p.is_file() and sha256_of(p) == entry["sha256"]


def fetch(cache_dir: Path, sources: set[str] | None = None) -> int:
    manifest = load_manifest()
    failures = 0
    for entry in manifest["datasets"]:
        if sources and entry["source"] not in sources:
            continue
        target = cache_path(cache_dir, entry)
        if is_cached(cache_dir, entry):
            print(f"cached  {entry['id']}")
            continue
        src = manifest["sources"][entry["source"]]
        url = src["url_template"].format(commit=src["commit"], path=urllib.parse.quote(entry["path"]))
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".part")
        try:
            with urllib.request.urlopen(url, timeout=120) as resp, tmp.open("wb") as out:
                out.write(resp.read())
        except Exception as exc:  # network errors are reported, not fatal per file
            print(f"FAILED  {entry['id']}: {exc}", file=sys.stderr)
            failures += 1
            continue
        digest = sha256_of(tmp)
        if digest != entry["sha256"]:
            tmp.unlink()
            print(f"FAILED  {entry['id']}: sha256 {digest} != pinned {entry['sha256']}", file=sys.stderr)
            failures += 1
            continue
        tmp.replace(target)
        print(f"fetched {entry['id']}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    ap.add_argument("--source", action="append", help="limit to one source key (repeatable)")
    args = ap.parse_args()
    failures = fetch(args.cache_dir, set(args.source) if args.source else None)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
