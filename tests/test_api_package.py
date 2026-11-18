"""lsadra.api is the API's home; lsadra.ui is only an alias for open branches."""

import importlib

import pytest

MOVED = {
    "lsadra.ui.alert_stream": "lsadra.api.alert_stream",
    "lsadra.ui.api_dashboard": "lsadra.api.dashboard",
    "lsadra.ui.api_identity": "lsadra.api.identity",
    "lsadra.ui.api_models": "lsadra.api.models",
    "lsadra.ui.data_layer": "lsadra.api.data_layer",
    "lsadra.ui.utils.report_generator": "lsadra.api.report_generator",
}


@pytest.mark.parametrize("old,new", sorted(MOVED.items()))
def test_old_path_is_the_same_module(old, new):
    assert importlib.import_module(old) is importlib.import_module(new)


def test_from_import_and_patch_share_state():
    from unittest.mock import patch

    from lsadra.ui import alert_stream as old_stream
    from lsadra.api import alert_stream as new_stream

    assert old_stream.alert_hub is new_stream.alert_hub
    with patch("lsadra.ui.api_dashboard.get_dashboard_kpis", return_value={"x": 1}):
        import lsadra.api.dashboard as dashboard

        assert dashboard.get_dashboard_kpis() == {"x": 1}


def test_streamlit_modules_do_not_resolve():
    for gone in ("lsadra.ui.dashboard", "lsadra.ui.pages", "lsadra.ui.components"):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(gone)


def test_server_serves_the_moved_routers():
    from fastapi.testclient import TestClient

    import server

    client = TestClient(server.app)
    # Unauthenticated, but routed: 401/403, never 404.
    for path in ("/api/dashboard/kpis", "/api/models/status"):
        assert client.get(path).status_code in (401, 403), path
    assert client.get("/api/dashboard/no-such-route").status_code == 404
