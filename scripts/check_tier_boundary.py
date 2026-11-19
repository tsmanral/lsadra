"""Lite/Team import boundary check (ADR 0008).

LSADRA Lite (this repository, AGPL-3.0) must never depend on code from the
private Team edition. Team code lives in a separate private repository under the
reserved ``lsadra_team`` namespace, so the rule is mechanical: no Python file in
this repository may import ``lsadra_team`` (or the reserved ``lsadra.team``
sub-package), statically or through ``importlib``/``__import__``, no frontend
source may import the reserved ``@lsadra/team`` scope, and neither reserved
package may exist here.

Run it directly (exit status 1 on any violation) or through
``tests/test_tier_boundary.py``, which CI runs on every pull request:

    python scripts/check_tier_boundary.py
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Python module prefixes that belong to the Team edition.
FORBIDDEN_MODULES: tuple[str, ...] = ("lsadra_team", "lsadra.team")

# npm scope reserved for Team frontend packages.
FORBIDDEN_JS_SPECIFIER = "@lsadra/team"

# Paths that would mean Team code had been placed inside the Lite repository.
RESERVED_PATHS: tuple[str, ...] = ("lsadra_team", "lsadra/team")

# Directories never scanned: dependencies, build output, caches, VCS metadata.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)

JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

# import ... from "x" | import "x" | export ... from "x" | import("x") | require("x")
_JS_IMPORT_RE = re.compile(
    r"""(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)(['"`])([^'"`]+)\1"""
)

_DYNAMIC_IMPORT_FUNCS = frozenset({"import_module", "__import__"})


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.detail}"


def _is_forbidden(module: str, forbidden: tuple[str, ...]) -> bool:
    return any(module == f or module.startswith(f + ".") for f in forbidden)


def _iter_files(root: Path, suffixes: tuple[str, ...]) -> Iterator[Path]:
    # os.walk with pruning, so a local node_modules or venv is never descended into.
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.endswith(suffixes):
                yield Path(dirpath) / name


def python_violations(
    source: str, rel_path: str, forbidden: tuple[str, ...] = FORBIDDEN_MODULES
) -> list[Violation]:
    """Return every import of a forbidden module in one Python source file."""
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        # Ruff's E9 rule reports syntax errors; don't hide a file from this check.
        return [Violation(rel_path, exc.lineno or 0, "could not parse file")]

    found: list[Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_forbidden(alias.name, forbidden):
                    found.append(Violation(rel_path, node.lineno, f"import {alias.name}"))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                if _is_forbidden(node.module, forbidden):
                    found.append(Violation(rel_path, node.lineno, f"from {node.module} import"))
                else:
                    # `from lsadra import team` reaches the reserved sub-package too.
                    for alias in node.names:
                        full = f"{node.module}.{alias.name}"
                        if _is_forbidden(full, forbidden):
                            found.append(
                                Violation(
                                    rel_path,
                                    node.lineno,
                                    f"from {node.module} import {alias.name}",
                                )
                            )
        elif isinstance(node, ast.Call):
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id
                if isinstance(func, ast.Name)
                else None
            )
            if name in _DYNAMIC_IMPORT_FUNCS and node.args:
                arg = node.args[0]
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and _is_forbidden(arg.value, forbidden)
                ):
                    found.append(Violation(rel_path, node.lineno, f"{name}({arg.value!r})"))
    return found


def js_violations(
    source: str, rel_path: str, specifier: str = FORBIDDEN_JS_SPECIFIER
) -> list[Violation]:
    """Return every import of the reserved Team npm scope in one JS/TS file."""
    found: list[Violation] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        for match in _JS_IMPORT_RE.finditer(line):
            target = match.group(2)
            if target == specifier or target.startswith(specifier + "/"):
                found.append(Violation(rel_path, lineno, f"imports {target!r}"))
    return found


def check(root: Path = REPO_ROOT) -> list[Violation]:
    """Scan the repository at ``root`` and return every boundary violation."""
    violations: list[Violation] = []

    for reserved in RESERVED_PATHS:
        if (root / reserved).exists():
            violations.append(
                Violation(reserved, 0, "reserved Team path exists in the Lite repository")
            )

    for path in _iter_files(root, (".py",)):
        rel = path.relative_to(root).as_posix()
        violations.extend(python_violations(path.read_text(encoding="utf-8"), rel))

    for path in _iter_files(root, JS_SUFFIXES):
        rel = path.relative_to(root).as_posix()
        violations.extend(js_violations(path.read_text(encoding="utf-8"), rel))

    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root to scan")
    args = parser.parse_args(argv)

    violations = check(args.root)
    if violations:
        print("Lite code must not depend on Team-only code (ADR 0008):", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("Tier boundary OK: no Lite code depends on Team-only code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
