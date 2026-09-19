# Phase 4 — Real Async Scan Engine, Lifecycle, Coverage, Cancellation

**Date:** 2026-09-19
**Repo:** `D:\CyberAgent`
**Baseline:** `docs/PHASE_3_IMPLEMENTATION.md` (completed 2026-09-19) ·
`docs/PHASE_4_REALITY_AUDIT.md` (the "before" audit).

## Goal

Turn the fire-and-forget synchronous executor + log-blob progress into a genuine
**asynchronous, staged scan engine**: a persisted job lifecycle, a real background worker
with a job registry and cooperative cancellation, structured progress/coverage, honest tool
inventory, granular SSE events, a configurable `POST /scans` job model, and a security-ops
frontend that reflects reality (no theatrical agent logs, no "AI copilot" billing).

**Hard rule (unchanged from Phase 3):** no observation ⇒ no finding; no tool output is ever
fabricated. `Not Installed` tools are reported and never faked.

## Design decisions

- **Scan = a job.** `Scan` carries a fine-grained `stage` lifecycle
  (`queued → starting → recon → discovery → service_scan → http_scan →
  vulnerability_scan → analysis → reporting → completed | partial | failed | cancelled`)
  plus `progress` (JSON counters) and `coverage` (§ `app/agents/lifecycle.py`).
  `status` is *derived* from stage so legacy consumers (`/scans/list`, dashboard) keep working.
- **Real worker in `app/workers/tasks.py`.** A module-level `ThreadPoolExecutor` with a
  `ScanJobRegistry` (registry of running/future jobs), `cancel_scan(scan_id)`, and a
  `ScanCancelled` exception that unwinds the pipeline cooperatively. Jobs set
  `cancel_requested` in the DB before/after cancellation so SSE and detail views see it.
- **Progress is real.** Counters only move when a stage/tool actually starts & completes.
  `coverage = completed_tasks/planned_tasks`; nothing hardcoded. `compute_coverage` returns
  `None` when there is nothing to measure yet.
- **Scope is enforced at enqueue time AND re-checked during discovery.** `_in_scope_hosts`
  filters discovered hosts back to the authorized project scope, so a scan that discovers
  an out-of-scope host skips it rather than scanning it.
- **Config-driven jobs (`POST /scans`, `ScanCreate`).** Body: `{target, tools: {t: bool},
  severity?, profile?}`. `tools` restricts which adapters participate; the config is
  persisted in `scan_config` (including `simulation`) and honored by the worker.
  `POST /scans/trigger` remains as a backward-compatible default-config path.
- **SSE events endpoint (`GET /scans/{id}/events`).** Emits typed events **only when they
  change**, derived from persisted rows: `stage`, `tool`, `finding`, `progress`, `done`,
  `error`. Never invents transitions. `GET /scans/{id}/stream` (log tailing) retained.
- **Cancellation (`POST /scans/{id}/cancel`).** Terminal stages answer immediately;
  otherwise `cancel_scan` requests cancellation and the worker stops between stages/tools.
  Rows that never enqueued are marked cancelled without a worker.
- **Tool inventory (`GET /tools/inventory`).** Honest `shutil.which` + version probes per
  adapter, plus stdlib probes, plus current `simulation_mode` (§ `app/tools/inventory.py`).
- **Coarse status mapping:** queued→Pending; completed/partial/failed/cancelled→
  Completed/Partially Completed/Failed/Cancelled; everything else→Running.

## What changed

### Backend
- `database/models.py` + `alembic/versions/5c1d34a9e72f_scan_job_lifecycle.py` —
  `Scan.stage`, `progress`, `coverage`, `scan_config`, `started_at`, `cancelled_at`,
  `cancel_requested`, `error`, `updated_at`; migration head.
- `app/agents/lifecycle.py` (new) — stage constants, `is_terminal`, `coarse_status`,
  `empty_progress`, `compute_coverage`.
- `app/workers/tasks.py` (rewritten) — `trigger_background_scan(scan_id, simulation=...,
  config=...)`, `ScanJobRegistry`, `cancel_scan` (returns coherence truth), `ScanCancelled`.
- `app/agents/workflow.py` (rewritten) — staged, cancellable, config-aware pipeline;
  out-of-scope host filtering; per-stage tool execution; progress/coverage updates; factual
  log lines (no theatrical agent banners).
- `app/tools/scanner_tools.py` — adapter contract + `is_tool_installed`; `Not Installed`
  results kept honest; no synthetic recon in real mode.
- `app/tools/inventory.py` (new) — live tool/version inventory.
- `app/api/scans.py` — `POST /scans` (+`ScanCreate` config), `GET /scans` detail
  (stage/progress/coverage/scan_config/tools/findings/observations_count), `GET /scans/
  coverage`, `GET /scans/{id}/coverage`, `GET /scans/{id}/observations`,
  `GET /scans/{id}/findings`, `GET /scans/{id}/events` (SSE), `POST /scans/{id}/cancel`,
  `GET /scans/{id}/stream` retained; `GET /scans/summary` + `/list` preserved.
- `app/api/tools.py` (new) — `/tools/inventory`; registered in `app/main.py`.
- **Route-order fix:** `/summary` (a static route) is registered *before* `/{scan_id}`;
  FastAPI `int` path params shadow static routes and would 422 otherwise.

### Frontend
- `src/pages/NewScan.tsx` — config panel: tool toggles (8 scanners), severity floor,
  profile select; `POST /scans`; live SSE via `/scans/{id}/events`; stage/progress/
  coverage/score readout; cancel button; scope manager; tool-status column.
- `src/pages/Scans.tsx` — detail via `GET /scans/{id}` + `/coverage`; pipeline lifecycle
  timeline; tool pipeline chips (NOT INSTALLED honest); findings with severity/state/
  evidence provenance (`evidence_observation_ids`); cancel; live event feed;
  privileged to view persisted logs.
- `src/pages/ToolHealth.tsx` (new) — `/tools/inventory` stats + per-category cards,
  honest INSTALLED / NOT INSTALLED badges, SIMULATION/REAL banner.
- `src/pages/AIChat.tsx` + `layouts/DashboardLayout.tsx` — renamed **AI Chat → Assessment
  Assistant**; page copy now states it is a deterministic rule-based assistant over
  persisted findings (no LLM claim).
- `src/App.tsx` — `/tools` route registered.
- `frontend/.env` — `VITE_API_URL=http://127.0.0.1:8003` (backend moved off 8000/8001).

### Tests (`backend/tests/test_phase4_engine.py`, new — 11 tests)
Coverage honesty, SSE change-only events, cancellation-no-zombie, two-user isolation on
Phase 4 endpoints, out-of-scope host skipping, NOT_INSTALLED never inflating coverage /
never failing the scan, queued-job immediacy + config persistence, evidence provenance
linking, inventory-vs-`shutil.which`, stale-row cancel, terminal-SSE done event.
Full suite: **109 passed**.

## Verification

- Backend suite: `backend/venv\Scripts\python.exe -m pytest -q` → **109 passed**.
- Migration parity: `alembic upgrade head` then `alembic check` → "No new upgrade
  operations detected"; HEAD_REVISION `5c1d34a9e72f`.
- Live real-mode run (backend on 127.0.0.1:8003, `SIMULATION_MODE=false`):
  - `POST /scans` `{target:127.0.0.1}` → queued → Completed, coverage 36.36,
    score 100, 0 findings, 11 observations; all external tools `Not Installed`,
    stdlib probes `Completed`.
  - `POST /scans` with `{tools:{nmap:false}, severity:high, profile:recon}` → Job 18:
    nmap excluded (`total_tools=7`), config persisted, Completed, coverage 40.0.
  - Cancel flow: running scan → cancels → stage `cancelled`, `cancelled_at` set,
    no zombie tool rows.
- Frontend: `npm run build` (tsc + vite) passes.

## Run it

1. `backend`: activate `venv`, `alembic upgrade head`, start uvicorn on 8003 with
   `SIMULATION_MODE` as desired (false = real probes, honest NOT INSTALLED).
2. `frontend`: `npm install && npm run dev` (`VITE_API_URL` already points at 8003).
3. Add a target to Authorized Scope, queue a scan with your tool set, watch the live
   pipeline events, and open `Tool Health` to see real availability.

## Explicitly not in scope (per brief — STOP AFTER PHASE 4)

Phase 5 items intentionally not started: multi-tenancy SaaS hardening, real Postgres
deployment, distributed workers/queue broker, LLM/RAG copilot, CI/CD, Docker/K8s,
real PDF generation, cloud secrets vault.