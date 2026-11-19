"""Lite/Team import boundary (ADR 0008).

The real check is ``scripts/check_tier_boundary.py``. The first test runs it on
this repository; the rest prove it catches each way Lite code could reach Team
code, so the boundary cannot silently stop working.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "check_tier_boundary", REPO_ROOT / "scripts" / "check_tier_boundary.py"
)
boundary = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = boundary
_spec.loader.exec_module(boundary)


def test_lite_repository_does_not_depend_on_team_code():
    violations = boundary.check(REPO_ROOT)
    assert violations == [], "\n".join(str(v) for v in violations)


@pytest.mark.parametrize(
    "source",
    [
        "import lsadra_team\n",
        "import lsadra_team.fleet as fleet\n",
        "from lsadra_team import sso\n",
        "from lsadra_team.tenants.models import Tenant\n",
        "import lsadra.team\n",
        "from lsadra.team.rbac import Policy\n",
        "from lsadra import team\n",
        "import importlib\nimportlib.import_module('lsadra_team.sso')\n",
        "from importlib import import_module\nimport_module('lsadra.team')\n",
        "__import__('lsadra_team')\n",
        "def f():\n    import lsadra_team\n",
        "try:\n    import lsadra_team\nexcept ImportError:\n    pass\n",
    ],
)
def test_python_imports_of_team_code_are_caught(source):
    assert boundary.python_violations(source, "x.py"), source


@pytest.mark.parametrize(
    "source",
    [
        "import lsadra\n",
        "from lsadra.auth import require_role\n",
        "import lsadra_teamwork\n",
        "from lsadra import teams\n",
        "from . import team\n",
        "name = 'lsadra_team'\n",
    ],
)
def test_ordinary_lite_imports_are_allowed(source):
    assert boundary.python_violations(source, "x.py") == []


@pytest.mark.parametrize(
    "source",
    [
        "import { Fleet } from '@lsadra/team';\n",
        'import Sso from "@lsadra/team/sso";\n',
        "export { Tenant } from '@lsadra/team/tenants';\n",
        "import '@lsadra/team/styles.css';\n",
        "const m = await import('@lsadra/team');\n",
        "const t = require('@lsadra/team');\n",
    ],
)
def test_frontend_imports_of_team_code_are_caught(source):
    assert boundary.js_violations(source, "x.ts"), source


@pytest.mark.parametrize(
    "source",
    [
        "import { api } from './services/api';\n",
        "import React from 'react';\n",
        "import x from '@lsadra/teamwork';\n",
    ],
)
def test_ordinary_frontend_imports_are_allowed(source):
    assert boundary.js_violations(source, "x.ts") == []


def test_check_scans_a_tree_and_skips_dependencies(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "ok.py").write_text("import lsadra\n", encoding="utf-8")
    (tmp_path / "pkg" / "bad.py").write_text("from lsadra_team import x\n", encoding="utf-8")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "bad.tsx").write_text("import t from '@lsadra/team';\n", encoding="utf-8")
    # A vendored dependency is not Lite code and must not be scanned.
    vendored = tmp_path / "web" / "node_modules" / "dep"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("require('@lsadra/team');\n", encoding="utf-8")

    found = {(v.path, v.line) for v in boundary.check(tmp_path)}
    assert found == {("pkg/bad.py", 1), ("web/bad.tsx", 1)}


def test_reserved_team_package_paths_are_rejected(tmp_path):
    (tmp_path / "lsadra" / "team").mkdir(parents=True)
    (tmp_path / "lsadra_team").mkdir()
    paths = {v.path for v in boundary.check(tmp_path)}
    assert paths == {"lsadra/team", "lsadra_team"}


def test_cli_exit_status(tmp_path, capsys):
    assert boundary.main(["--root", str(tmp_path)]) == 0
    (tmp_path / "bad.py").write_text("import lsadra_team\n", encoding="utf-8")
    assert boundary.main(["--root", str(tmp_path)]) == 1
    assert "bad.py:1" in capsys.readouterr().err
