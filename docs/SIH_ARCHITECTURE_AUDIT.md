# SIH26163 — World Monitor Security Assessment: Architecture Audit

**Repository:** `D:\CyberAgent` (CyberAgent — Autonomous AI Security Copilot)
**Audit date:** 2026-09-19
**Mode:** Read-only audit. No production code modified. No tests created.
**Committer baseline:** single commit `f874173` ("Initial commit"); working tree had pre-existing local changes (see §5).

---

## 1. Scope, method and honesty note

This audit inspects every file in the repository and maps each major architecture
component against the production-grade target expected of the **SIH26163 World Monitor
Security Assessment** platform.

> **Important caveat:** No `SIH26163` specification, diagram, ADR, or requirements
> document exists anywhere in the repository (see §2). The "Target" column below is
> therefore defined from two legitimate in-repo sources only:
> 1. The component taxonomy requested for this audit (backend, frontend, DB/migrations,
>    workers, scanners, auth/RBAC, reports, AI/ML, config/env, tests, Docker/compose, docs); and
> 2. Capability claims made by `README.md`.
>
> Nothing is inferred about external systems (e.g., the live `worldmonitor.app` map
> service or its Docker container occupying port 8000 — neither is part of this repo).

---

## 2. Complete repository tree (as inspected)

```
D:\CyberAgent
├── .gitignore
├── README.md
├── ca.png                      (untracked, 1.2 MB, stray artifact)
├── venv/                       (empty venv — pip only; NOT the runtime env)
├── backend/
│   ├── venv/                   (real runtime venv: fastapi, uvicorn, sqlalchemy, pydantic, python-dotenv)
│   ├── cyberagent.db           (SQLite, generated at runtime)
│   ├── app/
│   │   ├── main.py             (FastAPI app factory, CORS, router mounting)
│   │   ├── agents/workflow.py  (orchestrate_scan: Planner→Recon→Scan→AI→Report)
│   │   ├── api/scans.py        (/scans/* trigger/list/details/stream)
│   │   ├── api/auth.py         (/auth/* profile/assets)
│   │   ├── api/chat.py         (/chat/* query/history)
│   │   ├── api/reports.py      (/reports/* list/markdown/json/html/pdf)
│   │   ├── tools/scanner_tools.py (subfinder, assetfinder, dnsx, nmap, httpx, nuclei, gau, whatweb)
│   │   └── workers/tasks.py    (Celery-if-available else ThreadPoolExecutor)
│   └── database/
│       ├── connection.py       (engine, session, init_db + seed)
│       ├── models.py           (8 SQLAlchemy models)
│       └── schemas.py          (pydantic ScanRequest with target validator)
│   └── (no __init__.py anywhere; packages work as namespace packages under backend cwd)
├── frontend/
│   ├── index.html, package.json, package-lock.json
│   ├── postcss.config.js, tailwind.config.js, tsconfig.json   (NO vite.config.ts)
│   ├── public/  (favicon.png, favicon.svg, icons.svg, logo.png)
│   └── src/
│       ├── main.tsx          (real entry point)
│       ├── App.tsx           (router, auth gate)
│       ├── index.css         (Tailwind v4 + theme)
│       ├── layouts/DashboardLayout.tsx
│       ├── pages/ Auth, Dashboard, NewScan, Scans, Assets, Reports, AIChat, KnowledgeBase, Settings (.tsx)
│       └── DEAD VITE TEMPLATE FILES: main.ts, counter.ts, style.css, assets/*.svg, assets/hero.png
└── (NO docs/, tests/, migrations/, Dockerfile, docker-compose, CI, .env, requirements.txt)
```

**Exact files inspected** (source files, 100% of repo):

| Area | Files |
|---|---|
| Backend HTTP | `backend/app/main.py`, `backend/app/api/scans.py`, `backend/app/api/auth.py`, `backend/app/api/chat.py`, `backend/app/api/reports.py` |
| Backend engine | `backend/app/agents/workflow.py`, `backend/app/tools/scanner_tools.py`, `backend/app/workers/tasks.py` |
| Database | `backend/database/connection.py`, `backend/database/models.py`, `backend/database/schemas.py`, `backend/cyberagent.db` (schema inspection) |
| Frontend | `frontend/src/App.tsx`, `main.tsx`, `main.ts`, `counter.ts`, `index.css`, `style.css`, `layouts/DashboardLayout.tsx`, all 9 `pages/*.tsx` |
| Frontend config | `package.json`, `tsconfig.json`, `tailwind.config.js`, `postcss.config.js`, `index.html`, `.gitignore` |
| Root | `README.md`, `.gitignore`, venv contents, git log/status |

---

## 3. Baseline test result

**There is no test suite in the repository.**

- `pytest` is not installed in `backend/venv` (`No module named pytest`) and no `test_*.py` / `*_test.py` / `conftest.py` / `pytest.ini` / `tox.ini` / `setup.cfg` exist.
- `frontend/package.json` defines only `dev`, `build`, `preview` scripts — **no `test`, no `lint`, no `typecheck` script**.
- No JS/TS test framework (`vitest/jest/playwright`) in `package-lock.json`.

Baseline evidence collected:
- Backend imports cleanly: `import app.main` → OK (under `backend/` cwd).
- Registered routes enumerated below (§4).
- SQLite schema: tables `users, projects, assets, scans, tool_results, vulnerabilities, reports, chat_history`. No `alembic_version` table.
- Frontend type-check was run as an ad-hoc sanity check during a prior debugging session: `tsc --noEmit` passes (informational only — not an official project test).

**Baseline verdict: 0 automated tests; suite run = "no tests collected / pytest not installed".**

---

## 4. Registered API routes (from live FastAPI app + source)

| Method | Route | Handler file |
|---|---|---|
| GET | `/` | `app/main.py` |
| GET | `/docs`, `/redoc`, `/openapi.json` | FastAPI built-in |
| POST | `/scans/trigger` | `api/scans.py` |
| GET | `/scans/list` | `api/scans.py` |
| GET | `/scans/{scan_id}/details` | `api/scans.py` |
| GET | `/scans/{scan_id}/stream` (SSE) | `api/scans.py` |
| GET | `/auth/profile` | `api/auth.py` |
| GET | `/auth/assets` | `api/auth.py` |
| POST | `/chat/query` | `api/chat.py` |
| GET | `/chat/history/{scan_id}` | `api/chat.py` |
| GET | `/reports/list` | `api/reports.py` |
| GET | `/reports/{scan_id}/markdown` | `api/reports.py` |
| GET | `/reports/{scan_id}/json` | `api/reports.py` |
| GET | `/reports/{scan_id}/html` | `api/reports.py` |
| GET | `/reports/{scan_id}/pdf` | `api/reports.py` |

**Total: 15 HTTP endpoints** (4 framework + 11 application, 1 of them SSE).

---

## 5. Component-by-component audit

Legend: ✅ exists  • ⚠ partial/stubbed  • ❌ missing

### 5.1 Backend application shell
1. **Existing implementation:** FastAPI app with CORS (`allow_origins=["*"]`, `allow_credentials=True`) and 4 routers mounted. Status endpoint `/`.
2. **File path:** `backend/app/main.py`
3. **API/routes:** §4.
4. **DB tables/models:** none directly.
5. **Tests:** none.
6. **Reuse:** ✅ The app factory and router-mounting pattern are reusable.
7. **Refactor:** ⚠ CORS `*` + `allow_credentials=True` is invalid per STARLETE/browser rules and must be scoped. No middleware (logging, request IDs, rate limiting, error handlers, tracing). No `__init__.py` in packages (fragile namespace imports; require cwd=`backend`).
8. **Missing:** ❌ request-id/tracing middleware, exception handlers, structured logging, startup/lifecycle beyond `init_db`, OpenAPI metadata hardening, a true settings bundle.

### 5.2 Database models
1. **Existing implementation:** 8 SQLAlchemy models: `User, Project, Asset, Scan, ToolResult, Vulnerability, Report, ChatHistory`. Relationships + cascade deletes. Seed logic in `init_db()`.
2. **File path:** `backend/database/models.py`, `backend/database/connection.py`
3. **API/routes:** n/a (ORM only).
4. **DB tables/models:** `users, projects, assets, scans, tool_results, vulnerabilities, reports, chat_history` (verified in `cyberagent.db`).
5. **Tests:** none.
6. **Reuse:** ✅ Model set is the strongest existing asset; directly reusable.
7. **Refactor:** ⚠ `completed_at` is never written (workflow never sets it). `reports.pdf_content` is a misnomer (holds markdown bytes). `chat_history` has no session/thread id. No `updated_at` soft-delete/audit columns. `Asset` lacks unique constraint (dedupe done in app code).
8. **Missing:** ❌ **Migrations** — no Alembic, no `alembic_version` table, schema evolves only via `create_all`. Target requires versioned migrations.

### 5.3 Input validation / schemas
1. **Existing implementation:** `ScanRequest` Pydantic model with target validator (IPv4 / CIDR / domain). `ChatPayload` in `api/chat.py`.
2. **File path:** `backend/database/schemas.py`
3. **API/routes:** used by `POST /scans/trigger`, `POST /chat/query`.
4. **DB tables/models:** n/a.
5. **Tests:** none.
6. **Reuse:** ✅ Target validation logic reusable.
7. **Refactor:** ⚠ Validator strips protocol/path/query silently (URLs collapse to bare host) and rejects ports/CIDR-v6. No max-length beyond Pydantic defaults; no domain/IP allow-list; no rate-limit/abuse controls.
8. **Missing:** ❌ business validation for scan options (tool selection, depth, tags), response schemas for every endpoint (most return bare dicts).

### 5.4 Background workers / Celery
1. **Existing implementation:** `trigger_background_scan(scan_id, simulation=True)` — attempts Celery (`from celery import Celery` guarded by try/except), falls back to module-level `ThreadPoolExecutor(max_workers=5)`. `orchestrate_scan` runs the 5-stage pipeline in a worker thread while HTTP returns immediately.
2. **File path:** `backend/app/workers/tasks.py`, `backend/app/agents/workflow.py`
3. **API/routes:** n/a (called by `POST /scans/trigger`; observed via `GET /scans/{id}/stream`).
4. **DB tables/models:** writes `Scan.logs`, `ToolResult`, `Vulnerability`, `Report`, `Asset`.
5. **Tests:** none.
6. **Reuse:** ✅ Thread-pool fallback is functional (verified by running scan #1 to completion).
7. **Refactor:** ⚠ The Celery branch is speculative (celery/redis not in venv, no `celery.py`, no beat/queue config, no task serialization/acks). Pipeline sleeps are hardcoded (`time.sleep(1…4)`). No cancellation, queue priority, retries, or per-scan isolation (single shared executor).
8. **Missing:** ❌ production task broker integration, queues, retry/backoff, task state machine, progress model decoupled from `Scan.logs` text, worker observability.

### 5.5 Scanner integrations
1. **Existing implementation:** 8 wrappers — `subfinder`, `assetfinder`, `dnsx`, `nmap`, `httpx`, `nuclei`, `gau`, `whatweb`. Each has `simulation=True` branch (deterministic mock data with `time.sleep`) and a `simulation=False` branch that shells out to the real binary via `subprocess.run` with a strictly list-based command (no shell=True).
2. **File path:** `backend/app/tools/scanner_tools.py`
3. **API/routes:** none — internal functions consumed by `workflow.py`.
4. **DB tables/models:** results land in `ToolResult`, `Vulnerability`, `Asset`.
5. **Tests:** none.
6. **Reuse:** ✅ Signature pattern (`run_<tool>(target, simulation) -> dict`) and subprocess parameterization are reusable.
7. **Refactor:** ⚠ Simulation data is hardcoded (identical SQLi/jQuery/CSP findings for every target). Real-mode parsers are naive line regexes (nmap/httpx/nuclei) and nuclei parsing is lossy (ignores template severity/CVE). Scanning is always invoked with `simulation=True` from the trigger endpoint — real mode is unreachable via API. `sanitize_input` mutates targets (strips legitimately useful chars). No auth for tools needing API keys (gau relies on env only). No tool version pinning, no output volume limits.
8. **Missing:** ❌ structured tool-result schema (JSON output), SCA/dependency scanner, technology/CVE enrichment (the `Settings` page hints at Shodan/OpenAI/Groq — none wired), rate-limit concurrency control, "World Monitor" domain-specific collectors (weather/nuclear/sanctions/outages/waterways/military — nothing in repo).

### 5.6 AI / ML ("AI Planner", "Copilot", "AI Analysis Agent")
1. **Existing implementation:** Nothing is AI. The "Planner", "AI Analysis Agent" and "Reporting Agent" are deterministic Python in `workflow.py`. Chat "AI" (`/chat/query`) is a keyword-matching if/elif rule tree with canned answers. `README.md` says LiteLLM is optional; it is not installed.
2. **File path:** `backend/app/api/chat.py`, `backend/app/agents/workflow.py`
3. **API/routes:** `POST /chat/query`, `GET /chat/history/{scan_id}`.
4. **DB tables/models:** `ChatHistory` (role/message only — no model name, tokens, latency, or metadata).
5. **Tests:** none.
6. **Reuse:** ⚠ Only the prompt-context assembly (building `vuln_context` from DB) is reusable as the future LLM context builder.
7. **Refactor:** ⚠ Replace keyword rules with a real provider interface (LiteLLM/OpenAI-compatible) behind the existing endpoint contract; move response generation out of the route handler.
8. **Missing:** ❌ LLM provider abstraction, model config, RAG/vector store, embeddings for Knowledge Base, guardrails/prompt-injection mitigations, token/usage accounting, evaluation harness for the "AI Analysis Agent".

### 5.7 Authentication / RBAC
1. **Existing implementation:** `get_current_user()` — reads an `Authorization` header **but ignores it** and always returns the seeded `demo-user-id`. Frontend `Auth.tsx` simulates login with `setTimeout(1200)` and sets `localStorage['cyberagent_session']`; `App.tsx` gates routing on that localstorage flag. `User` model has `id/email/created_at` only — no password, no role column (role is a hardcoded string returned by `/auth/profile`).
2. **File path:** `backend/app/api/auth.py`, `frontend/src/pages/Auth.tsx`, `frontend/src/App.tsx`, `backend/database/models.py`
3. **API/routes:** `GET /auth/profile`, `GET /auth/assets`.
4. **DB tables/models:** `users`, `projects` (user_id FK), `assets`.
5. **Tests:** none.
6. **Reuse:** ⚠ The `get_current_user` dependency-injection hook is the right seam; replace its body.
7. **Refactor:** ⚠ Full rewrite required — an HTML comment in code retains Supabase references; docs say "Supabase Authorization Token" but nothing validates JWT; `/auth/assets` returns every asset for every user (no project/user scoping); no RBAC; `/scans/*`, `/chat/*`, `/reports/*` have **no auth dependency at all**.
8. **Missing:** ❌ real identity provider or JWT verification, password hashing/signup, role/tenant model, per-user asset/scan isolation, secure session (no localStorage-flag auth), CSRF handling, audit log.

### 5.8 Reports
1. **Existing implementation:** Reports generated inside `workflow.py` at end of scan (markdown + HTML built from scan data; `json_content` = dict; `pdf_content` = **markdown bytes sent with `application/pdf` headers** — it is not a real PDF). Served by `/reports/*`.
2. **File path:** `backend/app/agents/workflow.py` (generation), `backend/app/api/reports.py` (serving)
3. **API/routes:** §4 `/reports/*` (list, markdown, json, html, pdf).
4. **DB tables/models:** `reports` table.
5. **Tests:** none.
6. **Reuse:** ✅ Markdown/JSON content generators and endpoints are reusable.
7. **Refactor:** ⚠ Handle pagination; real PDF engine needed; store audit/template info; report metadata (scan ref, author, retention).
8. **Missing:** ❌ scheduled/on-demand report export, compliance formats, download naming/template system, egress/storage (S3/MinIO) for large PDFs, report authorization.

### 5.9 Frontend application
1. **Existing implementation:** React 19 + Vite + TS + Tailwind v4, React Router 7, `@xyflow/react` topology graph, Recharts, Monaco, Lucide, framer-motion in deps. 9 pages + layout. All API calls are inline `fetch` with **hardcoded base URLs** (13 occurrences; previously `localhost:8000`, changed earlier to `http://127.0.0.1:8001` in the working tree — see git status).
2. **File path:** `frontend/src/**`, `frontend/package.json`
3. **API/routes (consumed):** every §4 endpoint except `/`.
4. **DB tables/models:** n/a.
5. **Tests:** none.
6. **Reuse:** ✅ Page skeletons (Scans list/detail, NewScan with live SSE terminal, Reports preview, Assets graph) are reusable UI.
7. **Refactor:** ⚠ API layer duplicated per page (should be a single `api.ts` client + env base URL); dashboard charts are **hardcoded static arrays** (`trendData`, `severityPieData`, `portsData`) not fed by backend; `Settings.tsx` has fake key fields and a no-op Save; `Auth` is fake; error states mostly `console.error` only.
8. **Missing:** ❌ centralized data/query layer (React Query/SWR), env-based config (`VITE_API_URL`), test framework & component tests, loading/error skeletons, accessibility pass, vite config, storybook/docs.

### 5.10 Configuration / environment handling
1. **Existing implementation:** `python-dotenv` `load_dotenv()` in `connection.py` (and `main.py`); `DATABASE_URL` env var with SQLite default; `REDIS_URL` default in `tasks.py`. No `.env` files committed (gitignored). No other config abstraction.
2. **File path:** `backend/database/connection.py`, `backend/app/workers/tasks.py`, `frontend/package.json`
3. **API/routes:** n/a.
4. **DB tables/models:** n/a.
5. **Tests:** none.
6. **Reuse:** ✅ dotenv + `DATABASE_URL` pattern.
7. **Refactor:** ⚠ Config is scattered; no pydantic-settings bundle; `Settings.tsx` UI keys persist nowhere; simulation flag is not env-driven (hardcoded `simulation=True` at the trigger).
8. **Missing:** ❌ `backend/requirements.txt` (README's pip line omits `python-dotenv`), `.env.example`, secrets management, signed settings schema, environment-delegated scanning mode.

### 5.11 Docker / orchestration
1. **Existing implementation:** none.
2. **File path:** n/a (no `Dockerfile`, `docker-compose.yml`, `.dockerignore` anywhere).
3. **API/routes:** n/a.
4. **DB tables/models:** n/a.
5. **Tests:** n/a.
6. **Reuse:** n/a.
7. **Refactor:** n/a.
8. **Missing:** ❌ everything — container images for backend/frontend, compose for API + worker + broker + DB, healthchecks, build stages, volume for SQLite, env injection. (Note: an unrelated "World Monitor" Docker container currently occupies host port 8000; it is outside this repo.)

### 5.12 Tests & CI/CD
1. **Existing implementation:** none.
2. **File path:** n/a.
3. **API/routes:** n/a.
4. **DB tables/models:** n/a.
5. **Tests:** n/a (see §3 baseline).
6. **Reuse:** n/a.
7. **Refactor:** n/a.
8. **Missing:** ❌ pytest + fastapi TestClient/httpx, unit tests for validator/tools/score math, integration test for the full scan pipeline against a temp SQLite DB, frontend component/e2e tests, GitHub Actions/CI, coverage gates.

### 5.13 Documentation
1. **Existing implementation:** `README.md` (setup + architecture bullet + simulation guardrails blurb) and the FastAPI auto-docs.
2. **File path:** `README.md`
3. **API/routes:** n/a.
4. **DB tables/models:** n/a.
5. **Tests:** n/a.
6. **Reuse:** ✅ setup steps largely accurate for the sim path.
7. **Refactor:** ⚠ README overstates production-readiness ("production-grade", "Celery task runner", "LiteLLM", multi-agent AI) vs. code reality (modal demo + mock).
8. **Missing:** ❌ API reference docs, DB schema doc, architecture diagram, security model doc, deployment doc, runbook, `docs/` folder (created by this audit).

---

## 6. Existing → Target mapping

Target scope: production-grade CyberAgent/World-Monitor security-assessment platform implied by README claims + the SIH26163 component checklist.

| # | Architecture component | Existing (verdict) | Target (SIH26163-expected) | Gap |
|---|---|---|---|---|
| 1 | API framework | FastAPI, 15 routes (✅) | Versioned, documented, typed responses, hardened CORS, middleware | Add versioning prefix, response schemas, middleware, fix CORS |
| 2 | Database | 8 SQLAlchemy tables, SQLite (✅) | Migrations, per-tenant isolation, audit columns, support Postgres | Alembic + model polish + prod DB driver |
| 3 | Migrations | none (❌) | Versioned, reproducible schema | Build from scratch |
| 4 | Background workers | ThreadPool + optional Celery shell (⚠) | Real queue/broker, retries, queues, supervisor, metrics | Wire Celery/Redis or replacement; formalize task model |
| 5 | Scanner integrations | 8 wrappers, sim-default (⚠) | Real scanner orchestration with structured output, versioned, rate-limited | Replace hardcoded mocks with real binary/structured parsing + feature flag |
| 6 | World-Monitor domain collectors | none (❌) | Conflict/bases/hotspots/nuclear/sanctions/weather/alerts/economic/waterways/outages/military/natural data ingestion & APIs | Entire subsystem absent |
| 7 | Authentication | mock, token ignored (❌) | Real identity + JWT/session + roles | Rebuild |
| 8 | RBAC / multi-tenancy | none; demo user only (❌) | Org/project/user scoping on every query | Rebuild |
| 9 | Reports | md/html/json + fake "pdf" (⚠) | Real PDF, compliance formats, async generation, storage | Replace PDF path, add storage/retention |
| 10 | AI / ML copilot | keyword rules, no LLM (❌) | Provider abstraction, LLM analysis, RAG over findings, usage tracking | Rebuild on existing `/chat/*` contract |
| 11 | Knowledge Base | static 4-article array (⚠) | Published, searchable, DB-backed articles, vector search | DB + API + embeddings |
| 12 | Frontend | React 19 SPA, 9 pages (✅) | Real data graphs, centralized API client, tests, a11y | API layer + live charts + tests; remove dead template files |
| 13 | Configuration | dotenv + defaults, scattered (⚠) | pydantic-settings schema, `.env.example`, secrets manager | Consolidate |
| 14 | Containerization | none (❌) | Dockerfile + compose for api/worker/db | Build from scratch |
| 15 | Tests | none (❌) | Backend + frontend suites, CI | Build from scratch |
| 16 | CI/CD | none (❌) | Lint, typecheck, test, build, deploy | Build from scratch |
| 17 | Documentation | README only (⚠) | API/docs, schema, deploy, runbook | Expand |

---

## 7. Architecture gaps (summary)

1. **No migrations** — `create_all` only; production schema drift unmanageable.
2. **No real authentication/RBAC** — every data route is either demo-user or unauthenticated; `auth.py` ignores the Authorization header.
3. **No real AI** — chat is hardcoded keywords; no LLM provider, RAG, or embeddings exist.
4. **Scans are simulations** — `scans.py:33` hardcodes `simulation=True`; real binaries unreachable from the API; mock findings are identical across all targets.
5. **No World-Monitor-specific data layer** — none of the layers named in the target (conflicts, bases, hotspots, nuclear, sanctions, weather, alerts, economic, waterways, outages, military, natural) exist as models, endpoints, or collectors.
6. **No tests, no CI, no Docker, no requirements.txt, no `.env.example`.**
7. **Reports PDF is faked** (markdown bytes with a PDF media type).
8. **`completed_at` never populated**; score math is deterministic but untested.
9. **Frontend talks to a hardcoded host:port in 13 places** (currently `127.0.0.1:8001`), charts are static, Settings save is a no-op.

---

## 8. Contradictions discovered

1. **README vs code:** README describes a "production-grade", Celery-backed, LiteLLM multi-agent AI scanner. Repo reality: modal demo, thread pool, no LLM, no Celery deps, all scans simulated.
2. **Auth claims vs behavior:** route docstring says "checks Supabase Authorization Token"; the code never inspects the token and always returns `demo-user-id`; frontend does a `setTimeout` "login".
3. **CORS config:** `allow_origins=["*"]` combined with `allow_credentials=True` is rejected by browsers/STARLETE semantics.
4. **`reports.pdf_content`:** column and endpoint advertise PDF; bytes are markdown.
5. **Simulation toggle UI vs backend:** `Settings.tsx` exposes "Orchestrator Simulation Mode" toggle that is never persisted or consulted (backend hardcodes `simulation=True`).
6. **API keys advertised, none consumed:** Settings UI shows OpenAI/Groq/Shodan key inputs; no code references them.
7. **Dead template code vs app:** `src/main.ts`, `src/counter.ts`, `src/style.css` (Vite starter) ship alongside `main.tsx`/`index.css`; `style.css` has brand-conflicting light theme.
8. **`venv/` duplication:** root `venv/` contains only pip; runtime deps live in `backend/venv` (README's pip instructions don't mention either).
9. **`chat.py` query ordering hack** (`...ascii if hasattr(...) else ...asc()`) — confusing dead attribute probe.
10. **Docker claim implied vs present:** an unrelated World Monitor container holds port 8000, but this repo has no container definitions at all.

---

## 9. Recommended implementation order

Phase 0 — Stabilize what exists
1. Add `backend/requirements.txt`, `.env.example`, pydantic-settings config bundle.
2. Enable first-class migrations (Alembic import of existing 8 tables).
3. Fix CORS, add request-id/logging/exception middleware.
4. Delete dead frontend template files (`main.ts`, `counter.ts`, `style.css`, unused `assets/*`).

Phase 1 — Correctness of the core pipeline
5. Real scanners behind a feature flag (`SIMULATION_MODE`), structured JSON parsing, keep subprocess list-arg security.
6. Populate `completed_at`; make score computation a pure, testable function.
7. Centralize frontend API client with `VITE_API_URL`; feed dashboard charts from `/scans/*` and `/auth/assets`.

Phase 2 — Tens of users / security
8. Real authentication + per-project authorization on all routes; remove demo-user bypass.
9. Run full scan integration test against a temp DB (first automated test wall).
10. Real report generation (PDF library) + report authorization + storage.

Phase 3 — AI/ML copilot
11. LLM provider abstraction behind `/chat/query`; RAG/vector store over findings + Knowledge Base; usage tracking.

Phase 4 — World-Monitor domain + scale
12. Data models + collectors/APIs for the 12 target layers (conflicts…natural) as a new subsystem; SSE/timeseries backend (worldmonitor.app-style `zoom`/`view`/`timeRange` query model).
13. Celery/Redis worker broker + queues; retries.
14. Docker images + compose for api/worker/db.

Phase 5 — Quality gates
15. Backend test suite (pytest + TestClient), frontend tests (vitest/RTL), CI pipeline, coverage.
16. Docs: API reference, schema, deployment runbook.

---

## 10. Statement of completeness

- All source files in the repository were read in full.
- No files, APIs, tables, or behaviors are claimed beyond what was found in code.
- No production code was modified and no dependencies were added during this audit.
- The working tree already contained uncommitted changes (frontend `8000→127.0.0.1:8001` URL fixes and `package-lock.json` resolution churn from prior work); these pre-date this audit phase and are unrelated to it.