from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from .models import Base, User, Project, Scan, Vulnerability, Asset, ToolResult, Report, ChatHistory
from app.config import settings

DATABASE_URL = settings.database_url

if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+pg8000://", 1)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_schema(engine=engine):
    """Fails loudly when the database has not been migrated.

    Production startup assumes the schema is managed by Alembic migrations.
    This function never creates, drops, or alters tables.
    """
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    expected = set(Base.metadata.tables.keys())
    missing = expected - existing
    if missing:
        raise RuntimeError(
            "Database schema is missing table(s): {}."
            " Run 'alembic upgrade head' before starting the application.".format(", ".join(sorted(missing)))
        )

def seed_defaults(db=None):
    """Idempotently seeds the demo user and Default Sandbox project.

    This does not create or drop any table; it only inserts rows when they
    do not exist yet. Safe to call on every startup.
    """
    owns_session = db is None
    if owns_session:
        db = SessionLocal()
    try:
        demo_user = db.query(User).filter(User.id == "demo-user-id").first()
        if not demo_user:
            demo_user = User(id="demo-user-id", email="demo@cyberagent.ai")
            db.add(demo_user)
            db.commit()
            db.refresh(demo_user)

        demo_project = db.query(Project).filter(Project.name == "Default Sandbox").first()
        if not demo_project:
            demo_project = Project(
                name="Default Sandbox",
                description="Default environment for testing target networks, subdomains, and assets.",
                user_id=demo_user.id
            )
            db.add(demo_project)
            db.commit()
            db.refresh(demo_project)

            # Add some seed assets
            assets = [
                Asset(project_id=demo_project.id, type="domain", value="sandbox.cyberagent.ai", metadata_json={"status": "active"}),
                Asset(project_id=demo_project.id, type="ip", value="104.244.42.1", metadata_json={"status": "resolved"}),
                Asset(project_id=demo_project.id, type="port", value="80/tcp", metadata_json={"service": "http", "product": "nginx"}),
                Asset(project_id=demo_project.id, type="port", value="443/tcp", metadata_json={"service": "https", "product": "nginx"}),
                Asset(project_id=demo_project.id, type="tech", value="React", metadata_json={"version": "19.0.0"}),
                Asset(project_id=demo_project.id, type="tech", value="FastAPI", metadata_json={"version": "0.115.0"}),
            ]
            db.add_all(assets)
            db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        if owns_session:
            db.close()