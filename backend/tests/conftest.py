import os
import tempfile

# ---------------------------------------------------------------------------
# Phase 1 test isolation.
#
# The application reads DATABASE_URL / SIMULATION_MODE / CORS_ORIGINS into
# module-level singletons (app.config.settings, database.connection.engine)
# at import time. So the environment MUST be prepared before any app module is
# imported, which is why the os.environ assignments below come first.
#
# Every test run uses a throwaway SQLite database created under the system
# temp directory. The development database (backend/cyberagent.db) is never
# opened by tests.
# ---------------------------------------------------------------------------
_TMP_DB_DIR = tempfile.mkdtemp(prefix="cyberagent_test_")
_TMP_DB = os.path.join(_TMP_DB_DIR, "test.db").replace(os.sep, "/")

os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SIMULATION_MODE"] = "true"
os.environ["CORS_ORIGINS"] = "http://localhost:5173,http://127.0.0.1:5173"

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from app.main import app
from database.connection import SessionLocal, engine

# backend/ is the parent of backend/tests/
BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    """Apply the real Alembic migration chain to the throwaway database.

    This guarantees the schema the app and the tests run against is exactly
    the one produced by 'alembic upgrade head'.
    """
    cfg = Config(os.path.join(BACKEND_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_ROOT, "alembic"))
    command.upgrade(cfg, "head")
    yield


@pytest.fixture(scope="session")
def client():
    """TestClient with lifespan startup enabled (verify_schema + seed_defaults).

    Using the context manager is required so the app's startup handlers run,
    mirroring how the real server boots.
    """
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def session():
    """Direct SQLAlchemy session bound to the throwaway test database."""
    s = SessionLocal()
    yield s
    s.close()