# CyberAgent

**Autonomous AI Security Copilot**

CyberAgent is a security assessment platform that orchestrates reconnaissance and
scanning utilities (Nmap, Nuclei, httpx, subfinder, assetfinder, dnsx, gau, WhatWeb)
behind a multi-agent planner workflow, with a React dashboard and live SSE log
streaming.

## Status

This repository is in **Phase 1 of an active stabilization effort**. The foundation
is currently: Web UI in React + Vite + TypeScript, backend API in FastAPI, data stored
in SQLite (Alembic-managed schema), scans running in simulation mode by default. The
security-scan *tools* are invoked through a simulated pipeline; **no live network
probing, real authentication, or production-grade reporting exists yet**. See
`docs/PHASE_1_IMPLEMENTATION.md` and `docs/SIH_ARCHITECTURE_AUDIT.md` for details.

## Architecture & Tech Stack

### Frontend (`frontend/`)
- React 19, Vite, TypeScript
- Tailwind CSS, Framer Motion
- React Flow (`@xyflow/react`), Recharts, Monaco Editor
- Backend base URL is configured via `VITE_API_URL` (see `frontend/.env.example`).

### Backend (`backend/`)
- FastAPI, SQLAlchemy 2, Pydantic v2
- Alembic migrations (`backend/alembic/`)
- Background scans via thread-pool executor (Celery only if optionally installed)
- SSE streaming for live scan logs

## Setup

### Prerequisites
- Python 3.14+
- Node.js 18+ and npm

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate                # Windows
# venv/bin/activate                  # macOS/Linux
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env                # adjust values if needed
alembic upgrade head                # create/migrate the database schema
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload
```

The backend API docs are available at `http://127.0.0.1:8001/docs`.

> Port convention: in this development environment host port `8000` is occupied by
> an external service, so the CyberAgent backend runs on `127.0.0.1:8001` and the
> frontend is configured accordingly (`VITE_API_URL=http://127.0.0.1:8001`). Always use
> `127.0.0.1`, not `localhost`, because `localhost` resolves to IPv6 `::1` here.

### Frontend

```bash
cd frontend
cp .env.example .env                # adjust VITE_API_URL if needed
npm install
npm run dev
```

Open `http://localhost:5173`.

### Testing

```bash
cd backend
python -m pytest -v
```

Tests run against a throwaway SQLite database created under the system temp
directory and never touch `backend/cyberagent.db`.

## Implementation Status

### Implemented (Phase 1 scope)
- Config-driven runtime settings via `backend/app/config.py` (`DATABASE_URL`,
  `SIMULATION_MODE`, `CORS_ORIGINS`, `REDIS_URL` reserved).
- Alembic-managed schema; startup runs `verify_schema()` (fails loudly if the
  database was not migrated) and idempotently seeds the demo user/"Default Sandbox"
  project via `seed_defaults()`.
- CORS configured from `CORS_ORIGINS` (no wildcard combined with credentials).
- Scan lifecycle: `completed_at` is populated on success and failure; simulation-mode
  output is consistently marked `[SIMULATION]`/`[SIMULATED]` in logs and tool results.
- Dependency manifests (`requirements.txt`, `requirements-dev.txt`) with pinned
  versions; `.env.example` templates for backend and frontend.
- pytest suite (28 tests) covering imports, CORS, schema/migrations, seeding,
  target validation, scan lifecycle, and simulation markers.
- Dead Vite template files removed; frontend API base URL centralized in `src/api.ts`.

### Planned (NOT yet implemented — Phase 2+)
- Real authentication/RBAC (current backend routes use a demo identity only).
- Live scanner integrations and real network execution (simulation mode stays the
  default until then).
- Real report generation (current PDF is a mock of the markdown source) and a
  durable report store.
- LLM/RAG-based AI analysis, Celery/Redis queueing, and containerization.
- CI pipeline.

## Security & Guardrails

- **Simulation mode is on by default.** While enabled, the scan pipeline produces
  explicit synthetic output marked `[SIMULATION]`/`[SIMULATED]`; do not treat any
  findings as a real security assessment.
- Command execution is parameterized (list-based subprocess arguments) to avoid
  shell injection if real tools are ever enabled.