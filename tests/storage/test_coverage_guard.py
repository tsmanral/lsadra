"""Guard: every public function in lsadra.storage.database is exercised here.

Introspects the module's public functions and statically checks (via ``ast``)
that each one is called as ``db.<name>(...)`` / ``seeded.<name>(...)`` in at
least one contract test module. Adding a storage function without a contract
test fails this guard.
"""

import ast
import inspect
from pathlib import Path

import lsadra.storage.database as database

SUITE_DIR = Path(__file__).parent
FIXTURE_NAMES = {"db", "seeded"}
EXPECTED_PUBLIC_COUNT = 57  # audit §13 baseline; update deliberately with new tests


def _public_functions():
    return {
        name
        for name, fn in inspect.getmembers(database, inspect.isfunction)
        if fn.__module__ == database.__name__ and not name.startswith("_")
    }


def _called_names(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    called = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in FIXTURE_NAMES
        ):
            called.add(node.func.attr)
    return called


def _coverage():
    by_module = {}
    for path in sorted(SUITE_DIR.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        by_module[path.stem] = _called_names(path)
    return by_module


def test_public_function_count_matches_audit_baseline():
    assert len(_public_functions()) == EXPECTED_PUBLIC_COUNT, sorted(_public_functions())


def test_every_public_storage_function_is_called_by_the_suite():
    called = set().union(*_coverage().values())
    missing = sorted(_public_functions() - called)
    assert missing == [], f"public storage functions with no contract test: {missing}"
