"""The core installs as a package: pyproject metadata, entry points, data dir."""

import os
import subprocess
import sys
import tomllib
from importlib import import_module
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


def test_root_server_module_is_the_package_app():
    import lsadra.app
    import server

    assert server is lsadra.app
    assert server.app is lsadra.app.app


def test_console_scripts_point_at_real_functions():
    scripts = PYPROJECT["project"]["scripts"]
    assert set(scripts) == {"lsadra-server", "lsadra-admin"}
    for target in scripts.values():
        module, func = target.split(":")
        assert callable(getattr(import_module(module), func)), target


def test_version_has_one_source():
    dynamic = PYPROJECT["tool"]["setuptools"]["dynamic"]
    assert "version" in PYPROJECT["project"]["dynamic"]
    assert dynamic["version"] == {"attr": "lsadra.__version__"}
    assert "version" not in PYPROJECT["project"]


def test_dependencies_come_from_the_base_requirements():
    dynamic = PYPROJECT["tool"]["setuptools"]["dynamic"]
    assert dynamic["dependencies"] == {"file": ["requirements/base.in"]}
    for line in (REPO / "requirements/base.in").read_text(encoding="utf-8").splitlines():
        # setuptools reads this file as plain requirement lines.
        assert not line.lstrip().startswith("-"), f"base.in can't use pip options: {line}"


def test_every_tracked_data_file_ships_in_the_package():
    patterns = PYPROJECT["tool"]["setuptools"]["package-data"]["*"]
    shipped = {p.removeprefix("*") for p in patterns}
    tracked = subprocess.run(
        ["git", "ls-files", "lsadra"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.split()
    missing = [
        f for f in tracked if not f.endswith(".py") and Path(f).suffix not in shipped
    ]
    assert not missing, f"not covered by package-data: {missing}"


def _config_paths(env_extra):
    env = {**os.environ, "LSADRA_DEV_MODE": "true", **env_extra}
    code = (
        "from lsadra import config;"
        "print(config.DATA_DIR); print(config.DB_PATH); print(config.MODEL_DIR);"
        "print(config.LOG_DIR)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO, env=env, capture_output=True, text=True,
        check=True,
    ).stdout.split("\n")
    return [Path(p) for p in out[:4]]


def test_data_dir_defaults_to_the_checkout():
    env = {"LSADRA_DATA_DIR": "", "LSADRA_LOG_DIR": " "}
    data, db, models, logs = _config_paths(env)
    assert data == REPO / "data"
    assert db == REPO / "data" / "sentinel_v3.db"
    assert models == REPO / "data" / "models"
    assert logs == REPO / "logs"


def test_data_dir_follows_the_environment(tmp_path):
    env = {"LSADRA_DATA_DIR": str(tmp_path / "d"), "LSADRA_LOG_DIR": str(tmp_path / "l")}
    data, db, models, logs = _config_paths(env)
    assert data == (tmp_path / "d").resolve()
    assert db.parent == data and models.parent == data
    assert logs == (tmp_path / "l").resolve()


def test_app_creates_its_model_folder_under_the_data_dir():
    source = (REPO / "lsadra" / "app.py").read_text(encoding="utf-8")
    assert 'Path("data' not in source, "paths must come from lsadra.config, not the cwd"
