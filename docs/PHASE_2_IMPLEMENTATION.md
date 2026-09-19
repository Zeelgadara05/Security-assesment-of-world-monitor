# Phase 2 — Authentication, Authorization, Scope, and Scanner Adapter Foundation

**Date:** 2026-09-19
**Repo:** `D:\CyberAgent`
**Baseline:** `docs/PHASE_1_IMPLEMENTATION.md` (Phase 1, completed 2026-09-19)

## Goal

Replace the demo/mock authentication with a real, zero-dependency auth layer, add
ownership/RBAC and per-project scope enforcement, persist session tokens (opaque,
hashed), and lay an honest scanner-adapter foundation that reports real tool states
(NOT INSTALLED / TIMEOUT / EXECUTION FAILED / PARSE FAILED) instead of fabricating
results — including a frontend auth flow and a reality audit.

## Scope guarding

**Explicitly NOT implemented in this phase** (still deferred): World Monitor
integration; LLM/RAG/ML; real report generation beyond storage; Docker/Compose; CI;
Postgres migration; new collectors; `passlib`/`bcrypt`/`jwt` dependencies (password
hashing and session tokens use Python stdlib only). No demo user is auto-created;
nothing is an "always authenticated" fallback. This is the final delivery phase —
the repository is left **stopped** (no Phase 3).

## Design decisions

- **Zero-dependency password hashing.** `hashlib.pbkdf2_hmac("sha256")`, 600 000
  iterations, random 16-byte salt, stored as
  `pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>` in `User.password_hash`.
- **Opaque session tokens.** 32-byte `secrets.token_hex()` returned once at login;
  only its SHA-256 digest is stored in the new `sessions` table (revocable,
  TTL-driven). No JWT, no signature-key management.
- **Token transport.** `Authorization: Bearer <token>` header (primary), plus a
  `?token=` query parameter accepted for SSE/EventSource and `<a download>` links,
  which cannot set headers. The server sets no cookies.
- **Per-user project + scope.** Each user gets a project implicitly
  (`get_or_create_user_project`). Scope = declared `Project.scope_json` list ∪
  discovered assets for that project, matching domains (exact or subdomain of a
  declared parent), IPv4 (exact), and CIDR (containment). Out-of-scope triggers are
  rejected with 403.
- **Ownership isolation.** `users → projects → scans → reports/tools/vulns/chat`.
  All foreign resources resolve to 404, never leak presence via 403.
- **RBAC.** Roles `user` / `admin`; admin endpoints `/auth/users` and
  `/auth/admin/overview` behind `require_admin`. Admin bootstrap is config-driven
  and disabled by default (`ADMIN_DISABLED`).
- **Scanner adapters.** `ScannerAdapter` base with per-tool subclasses, `is_tool_installed`
  via `shutil.which`, list-based `subprocess.run(..., shell=False)`, 90 s timeout,
  honest Nuclei `-json` line parsing (malformed output → PARSE FAILED, never
  coerced into findings). `SIMULATION_MODE=false` must never fall back to simulation.

## Completed work

### 1. Schema — auth/RBAC foundation
- `backend/database/models.py`:
  - `User.password_hash` (String(512), nullable for legacy rows) and `User.role`
    (String(50), default `"user"`).
  - `Project.scope_json` (JSON, default `[]`).
  - New `Session` model (`token_hash` unique indexed, `user_id` FK, `created_at`,
    `expires_at`, `revoked_at`).
- `backend/alembic/versions/e8244e2719f7_auth_and_rbac_foundation.py` (down_revision
  `d1c4eef2b66c`), edited to add `server_default="user"` for `role`; applied to the
  dev DB (`alembic upgrade head`).

### 2. Configuration
- `backend/app/config.py`: `SESSION_TTL_HOURS` (default 12), `ADMIN_EMAIL`,
  `ADMIN_PASSWORD`, `ADMIN_DISABLED`; `settings.admin_enabled`.

### 3. Auth core (new)
- `backend/app/core/security.py` — PBKDF2 `hash_password` / `verify_password`,
  `generate_session_token`, `hash_session_token`.
- `backend/app/core/auth.py` — `_extract_token` (header → cookie → query),
  `authenticate_session`, `get_current_user`, `require_admin`,
  `get_user_projects`, `get_or_create_user_project`, `get_owned_scan`,
  `get_project_for_asset`, `is_target_in_scope`.

### 4. Seeding
- `backend/database/connection.py` `seed_defaults()` rewritten: no demo user; creates
  the bootstrap admin only when `ADMIN_EMAIL` + `ADMIN_PASSWORD` are set and
  `ADMIN_DISABLED != "true"`. Idempotent, no DDL.

### 5. API rewrites
- `backend/app/api/auth.py`: `POST /auth/register` (201, min 8-char password),
  `POST /auth/login`, `POST /auth/logout` (revokes the presented session),
  `GET /auth/me` and `/auth/profile` alias, `GET /auth/assets` (owner-only),
  `GET /auth/users` (admin), `GET /auth/admin/overview` (admin).
- `backend/app/api/scans.py`: trigger is authenticated, tied to the user's project,
  and scope-checked (403 with explicit message); `/scans/list` filtered by
  ownership; `GET/POST /scans/scope` to declare scope; details + SSE stream via
  ownership check.
- `backend/app/api/reports.py`: ownership via `_get_owned_report`; list filtered to
  owned scan ids.
- `backend/app/api/chat.py`: ownership via `get_owned_scan`; **fixed a real bug** —
  history was ordered by `created_at.desc()` while the UI renders oldest-first
  (now `.asc()`); simulated assistant responses include `"simulated": True`.
- `backend/app/main.py`: CORS `allow_credentials=True` (explicit origins only).

### 6. Scanner adapter foundation
- `backend/app/tools/scanner_tools.py` rewritten: states
  `Completed/Not Installed/Execution Failed/Timeout/Parse Failed`,
  `ADAPTERS` registry (subfinder, assetfinder, dnsx, nmap, httpx, gau, whatweb,
  nuclei), `BINARY_TIMEOUT_SECONDS=90`, `sanitize_input` (strips shell
  metacharacters for real-execution paths), module `run_*` functions preserved
  (`run_dnsx(target, subdomains, simulation)`).
- `backend/app/agents/workflow.py`: `save_tool_result` maps adapter states to
  persisted `ToolResult.status` (`success→Completed`, `NOT_INSTALLED→Not Installed`,
  `TIMEOUT→Timeout`, `PARSE_FAILED→Parse Failed`, `EXECUTION_FAILED→Failed`).

### 7. Frontend auth flow
- `frontend/src/api.ts` — token storage (`sessionStorage.cyberagent_token`),
  `apiFetch` (attaches `Authorization: Bearer`, triggers logout on 401),
  `authUrl` (query-token version for SSE + downloads), `onUnauthorized` hook.
- `frontend/src/pages/Auth.tsx` — real login/register against the backend, backend
  error surface, min 8-char password on sign-up.
- `frontend/src/App.tsx` — session derived from the stored token; 401 anywhere
  clears the token and returns to the auth screen; logout revokes the session.
- `frontend/src/layouts/DashboardLayout.tsx` — real user + role from `/auth/me`
  (replaces hardcoded "SecAdmin / demo@cyberagent.ai / SA"); wired logout button.
- `frontend/src/pages/NewScan.tsx` — SSE stream authenticates via `?token=`;
  friendly 403 (out-of-scope) and 401 (expired session) messaging.
- `frontend/src/pages/{Dashboard,Scans,Reports,AIChat,Assets}.tsx` — all fetches
  route through `apiFetch`; report download links carry the token query param.
- `frontend/src/pages/Settings.tsx` — honest copy: placeholder keys are read-only
  and explicitly documented as unused; no phantom "saved" toast; simulation mode
  is informational (backend env controls it).

### 8. Tests (backend)
- Updated: `conftest.py` (register/login helpers, `auth_headers`, `other_auth_headers`,
  `admin_headers`, `add_scope`), `test_schema` (`sessions` table, HEAD revision
  `e8244e2719f7`), `test_seed` (config-driven admin, no demo user), `test_scan_lifecycle`,
  `test_tool_simulation_markers` (+ adapter state mapping), `test_root_cors`,
  `test_target_validator`, `test_imports`.
- New: `test_auth.py`, `test_authorization.py` (404 isolation), `test_rbac.py`
  (admin endpoints, 403s), `test_scope.py` (scope matrix + API 403 + per-user),
  `test_scanner_adapters.py` (availability, timeout, execution failure, parse
  failure, injection-safe args, non-fabrication).

## Validation performed

- `python -m pytest -q -p no:warnings` → **81 passed** (isolated temp SQLite DB,
  never touches `cyberagent.db`) — command run from `D:\CyberAgent\backend`.
- `npm run build` in `frontend/` → `tsc && vite build` clean (~755 ms; only the
  pre-existing >500 kB bundle-size advisory).
- **Migration parity:** fresh temp DB → `alembic upgrade head` applies both
  revisions; `alembic revision --autogenerate` then produced an **empty diff**
  (`upgrade()`/`downgrade()` are `pass`), proving the schema equals the models.
- **Live smoke (fresh temp DB, `127.0.0.1:8011`, `SIMULATION_MODE=true`,
  admin bootstrap enabled).** Note: `8001` was already occupied by a separate
  user process, so the validated instance ran on `8011`. All 27 checks passed:
  - Root reports `online` + `simulation_mode: true`.
  - Register → login (wrong password → 401) → `GET /auth/me` shows role `user`;
    unauthenticated calls → 401.
  - Trigger before scope → 403; `POST /scans/scope` adds `example.com`; trigger
    in-scope → 200 + `scan_id` (simulation marked); out-of-scope domain → 403;
    subdomain `api.example.com` → 200 (scope containment).
  - Cross-user isolation: user B sees empty scan list and gets 404 on A's scan.
  - SSE without token → 401; with `?token=` → 200 and streams events to
    completion; scan completes with `security_score` and `[SIMULATION]` logs.
  - Report list owned-scoped; markdown report fetches content.
  - Bootstrap admin logs in; `/auth/users` + `/auth/admin/overview` → 200;
    regular user on `/auth/users` → 403.
  - Logout revokes: `/auth/me` → 401 afterward.

## Regressions & risks

- Legacy user rows (pre-Phase-2) have `password_hash = NULL` and can never log in
  (no fabrication of credentials); they remain only as historical data.
- Pre-existing deprecation warnings (SQLAlchemy, Starlette, httpx TestClient) are
  out of scope.
- Frontend bundle stays above the 500 kB advisory (Monaco/Recharts) — unchanged.
- SSE 401 (revoked session) closes the stream on the client; the app re-authenticates
  on the next API 401. No live scanner binaries are installed on this host, so
  `SIMULATION_MODE=false` reports NOT INSTALLED for every real tool — by design.