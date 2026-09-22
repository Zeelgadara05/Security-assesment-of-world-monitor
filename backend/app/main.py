from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.connection import verify_schema, seed_defaults
from app.config import settings
from app.api import scans, chat, reports, auth, findings, tools, system, world_monitor, dashboard

app = FastAPI(
    title="CyberAgent API",
    description="Evidence-first security assessment platform. World Monitor and custom authorized targets run one engine; findings derive only from persisted observations.",
    version="1.0.0"
)

# CORS is configuration-driven. Credentials are allowed because login
# sessions may be delivered via cookie; the origin list is explicit (no
# wildcard), which keeps credentialed CORS safe.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
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
app.include_router(findings.router)
app.include_router(tools.router)
app.include_router(system.router)
app.include_router(world_monitor.router)
app.include_router(dashboard.router)

@app.get("/")
def read_root():
    return {
        "status": "online",
        "app": "CyberAgent",
        "tagline": "Security Assesment Tool",
        "docs": "/docs",
        "simulation_mode": settings.simulation_mode
    }