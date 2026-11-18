"""Deprecated alias for :mod:`lsadra.api`.

The REST/WebSocket modules moved from ``lsadra.ui`` to ``lsadra.api`` and the
legacy Streamlit dashboard was removed. Old import paths keep working while
branches written against them land: ``lsadra.ui.<old name>`` resolves to the
very same module object as its new home, so module state (the alert hub,
caches) and ``unittest.mock.patch`` targets are shared, not copied.

New code imports from ``lsadra.api``. Remove this package once nothing in the
repository imports ``lsadra.ui``.
"""

import importlib
import importlib.abc
import importlib.machinery
import sys
import types

_MOVED = {
    f"{__name__}.alert_stream": "lsadra.api.alert_stream",
    f"{__name__}.api_dashboard": "lsadra.api.dashboard",
    f"{__name__}.api_identity": "lsadra.api.identity",
    f"{__name__}.api_models": "lsadra.api.models",
    f"{__name__}.data_layer": "lsadra.api.data_layer",
    f"{__name__}.utils.report_generator": "lsadra.api.report_generator",
}
_EMPTY_PACKAGES = {f"{__name__}.utils"}


class _Alias(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in _MOVED or fullname in _EMPTY_PACKAGES:
            return importlib.machinery.ModuleSpec(fullname, self, is_package=fullname in _EMPTY_PACKAGES)
        return None

    def create_module(self, spec):
        if spec.name in _EMPTY_PACKAGES:
            module = types.ModuleType(spec.name)
            module.__path__ = []
            return module
        # The real module keeps its own __spec__ and __name__; the import
        # system only fills attributes that are missing.
        return importlib.import_module(_MOVED[spec.name])

    def exec_module(self, module):
        pass


if not any(isinstance(f, _Alias) for f in sys.meta_path):
    sys.meta_path.insert(0, _Alias())
