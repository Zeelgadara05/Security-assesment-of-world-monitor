from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.connection import init_db
from app.api import scans, chat, reports, auth

app = FastAPI(
    title="CyberAgent API",
    description="Autonomous AI Security Copilot Backend service orchestrating security scanning tools.",
    version="1.0.0"
)

# Enable CORS for frontend cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup DB initialization
@app.on_event("startup")
def on_startup():
    init_db()

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
        "docs": "/docs"
    }



