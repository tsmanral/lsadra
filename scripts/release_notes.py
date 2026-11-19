#!/usr/bin/env python3
"""Write the notes for a GitHub release, and check that the version agrees.

    python scripts/release_notes.py --tag v6.0.0 --owner tsmanral \\
        --digest sha256:... --out notes.md
    python scripts/release_notes.py --check         # version sources agree
    python scripts/release_notes.py --next-version  # version the next release gets

The notes are the hand-written ``docs/releases/<tag>.md`` when it exists,
followed by the block that tells users how to verify the signed image.
release.yml runs this after the image is built, so the digest is real; the
release dry-run runs it with a placeholder digest.

``--check`` fails when the version in ``lsadra/__init__.py`` (the single
source) differs from ``.release-please-manifest.json`` or the README's
"Current release" line, which release-please keeps in step.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTES_DIR = ROOT / "docs" / "releases"
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def package_version() -> str:
    """Read ``__version__`` from lsadra/__init__.py without importing the package."""
    tree = ast.parse((ROOT / "lsadra" / "__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets
        ):
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
    raise SystemExit("lsadra/__init__.py has no string __version__")


def manifest_version() -> str:
    data = json.loads((ROOT / ".release-please-manifest.json").read_text(encoding="utf-8"))
    return data["."]


def readme_version() -> str:
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
        if "x-release-please-version" in line:
            match = re.search(r"v(\d+\.\d+\.\d+)", line)
            if match:
                return match.group(1)
    raise SystemExit("README.md has no 'x-release-please-version' line with a version")


def next_version() -> str:
    """The version release-please will cut next: a pinned ``release-as``, else the current one."""
    config = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
    return config["packages"]["."].get("release-as") or package_version()


def check() -> list[str]:
    """Return a list of problems; empty when every version source agrees."""
    version = package_version()
    problems = []
    if not SEMVER.match(version):
        problems.append(f"lsadra.__version__ is not MAJOR.MINOR.PATCH: {version!r}")
    for name, other in (("manifest", manifest_version()), ("README", readme_version())):
        if other != version:
            problems.append(f"{name} says {other}, lsadra.__version__ says {version}")
    return problems


def verification_block(owner: str, digest: str) -> str:
    return "\n".join(
        [
            "### Verify the container image",
            "",
            "```bash",
            f"gh attestation verify oci://ghcr.io/{owner}/lsadra@{digest} --owner {owner}",
            "```",
            "",
        ]
    )


def build_notes(tag: str, owner: str, digest: str) -> str:
    if not re.match(r"^v\d+\.\d+\.\d+$", tag):
        raise SystemExit(f"not a release tag: {tag!r}")
    hand_written = NOTES_DIR / f"{tag}.md"
    parts = []
    if hand_written.exists():
        parts.append(hand_written.read_text(encoding="utf-8").rstrip() + "\n")
    parts.append(verification_block(owner, digest))
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="only check that version sources agree")
    parser.add_argument("--next-version", action="store_true", help="print the next release's version")
    parser.add_argument("--tag")
    parser.add_argument("--owner")
    parser.add_argument("--digest")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    if args.next_version:
        print(next_version())
        return 0

    if args.check:
        problems = check()
        for problem in problems:
            print(f"version mismatch: {problem}", file=sys.stderr)
        if not problems:
            print(f"version {package_version()}: lsadra, manifest and README agree")
        return 1 if problems else 0

    if not (args.tag and args.owner and args.digest and args.out):
        parser.error("--tag, --owner, --digest and --out are required for notes")
    args.out.write_text(build_notes(args.tag, args.owner, args.digest), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
