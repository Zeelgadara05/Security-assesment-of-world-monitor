"""Smoke tests: every app module imports and the FastAPI app is wired up."""

import app.config
import app.main
import app.api.scans
import app.api.reports
import app.api.chat
import app.api.auth
import app.workers.tasks
import app.agents.workflow
import app.tools.scanner_tools
import database.connection
import database.models
import database.schemas


def test_full_import_chain():
    assert app.main.app is not None


def test_cors_middleware_registered():
    names = [m.cls.__name__ for m in app.main.app.user_middleware]
    assert "CORSMiddleware" in names


def test_has_expected_router_count():
    assert len(app.main.app.routes) >= 9


def test_settings_loaded_from_config():
    s = app.config.settings
    assert s.simulation_mode is True  # set by conftest
    assert "http://localhost:5173" in s.cors_origins
    assert s.database_url.startswith("sqlite:///")