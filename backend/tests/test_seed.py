"""Startup seeding is idempotent and produces the Default Sandbox demo data."""

from database.connection import seed_defaults
from database.models import Asset, Project, User


def test_seed_creates_demo_data(client, session):
    # client fixture runs startup, which already called seed_defaults once
    user = session.query(User).filter(User.id == "demo-user-id").first()
    assert user is not None
    project = session.query(Project).filter(Project.name == "Default Sandbox").first()
    assert project is not None
    assert session.query(Asset).filter(Asset.project_id == project.id).count() >= 6


def test_seed_is_idempotent(session):
    counts = (
        session.query(User).count(),
        session.query(Project).count(),
        session.query(Asset).count(),
    )
    seed_defaults()
    assert (
        session.query(User).count(),
        session.query(Project).count(),
        session.query(Asset).count(),
    ) == counts


def test_trigger_uses_seeded_default_project(client):
    resp = client.post("/scans/trigger", json={"target": "example.com"})
    assert resp.status_code == 200
    assert resp.json()["simulation"] is True