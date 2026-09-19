from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.connection import verify_schema, seed_defaults
from app.config import settings
from app.api import scans, chat, reports, auth

app = FastAPI(
    title="CyberAgent API",
    description="Autonomous AI Security Copilot Backend service orchestrating security scanning tools.",
    version="1.0.0"
)

# CORS is configuration-driven. No wildcard is combined with credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup DB verification and seeding.
# The application assumes the database has already been migrated
# (alembic upgrade head). verify_schema fails loudly if tables are missing.
@app.on_event("startup")
def on_startup():
    verify_schema()
    seed_defaults()

# Include endpoints
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(chat.router)
app.include_router(reports.router)

@app.get("/")
def read_root():
    return {
        "status": "online",
        "app": "CyberAgent",
        "tagline": "Autonomous AI Security Copilot",
        "docs": "/docs",
        "simulation_mode": settings.simulation_mode
    }