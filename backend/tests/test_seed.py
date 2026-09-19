"""Startup seeding: configuration-driven admin bootstrap only.

Phase 2 removed the unconditional demo-user / Default Sandbox seed.  No
identity is ever created implicitly; an admin exists only when ADMIN_EMAIL and
ADMIN_PASSWORD are both explicitly configured.
"""

from database.connection import seed_defaults
from database.models import Project, User


def test_no_implicit_demo_user_or_project(client, session):
    # Startup ran seed_defaults() once; without admin config nothing is created.
    assert session.query(User).filter(User.id == "demo-user-id").first() is None
    assert session.query(Project).filter(Project.name == "Default Sandbox").first() is None


def test_seed_is_idempotent_without_config(session):
    counts = (session.query(User).count(), session.query(Project).count())
    seed_defaults()
    assert (session.query(User).count(), session.query(Project).count()) == counts


def test_config_driven_admin_bootstrap(session, monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "admin_email", "bootstrap-admin@test.local")
    monkeypatch.setattr(config.settings, "admin_password", "BootstrapPass123!")
    monkeypatch.setattr(config.settings, "admin_enabled", True)

    seed_defaults()
    admin = session.query(User).filter(User.email == "bootstrap-admin@test.local").first()
    assert admin is not None
    assert admin.role == "admin"
    assert admin.password_hash and admin.password_hash.startswith("pbkdf2_sha256$")

    # Idempotent: a second call does not duplicate the row.
    before = session.query(User).count()
    seed_defaults()
    assert session.query(User).count() == before

    # Clean up so later tests in the shared session are unaffected.
    session.delete(admin)
    session.commit()
