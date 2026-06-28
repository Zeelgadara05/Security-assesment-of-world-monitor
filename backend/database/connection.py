from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os
from .models import Base, User, Project, Scan, Vulnerability, Asset

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyberagent.db")

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

def init_db():
    Base.metadata.create_all(bind=engine)
    # Seed default user & demo project if not exists
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
    except Exception as e:
        print(f"Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()
