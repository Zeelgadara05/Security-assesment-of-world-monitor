# Phase 8 Baseline Audit & Implementation Plan

Scope: "World Monitor Integration Foundation & Real Assessment Pipeline", built on the
completed Phase 7 execution platform. This document is the inspection deliverable (Phase 8
execution mode: **no application code changes until implementation is approved**).

Repo root: `E:\SEMESTER 3\SIH\Security-assesment-of-world-monitor`

---

## 1. Current architecture (post-Phase 7)

- **API**: FastAPI app in `backend/app/main.py`; routers in `backend/app/api/` (`auth`, `scans`,
  `reports`, `tools`, `system`, `chat`, `findings`). All resource endpoints require auth;
  ownership enforced via `backend/app/core/auth.py` (`get_current_user`, `is_target_in_scope`).
- **Persistence**: SQLAlchemy, 8-alembic-revision chain (head `2c6e4ab9f71d`), models in
  `backend/database/models.py`. `connection.verify_schema()` fails loudly (never `create_all`);
  tests migrate a throwaway DB via `alembic upgrade head` in `conftest.py`.
- **Phase 7 pipeline** (`backend/app/orchestration/pipeline.py::orchestrate_scan_phase7`):
  real-scan background driver. 13 stages (`STAGE_ORDER`), preflight probe
  (`preflight.py`), typed event stream (`events.py`, `scan_events` table), tool executions with
  bounded/redacted telemetry (`executions.py`, `tool_executions`), deterministic assessment
  (`finding_rules.evaluate_observations` = simple rules; `app/assess/engine.run_assessment` =
  native registry-planned engine), validation records, cross-scan tracking, advisory-only
  `MLInference` (`app/ml/advisory.py`).
- **Native engine** (`app/assess/engine.py`): `SafeHttpClient` (scope-guarded, request-bounded
  `_MAX_REQUESTS=200`, `_MAX_ENDPOINTS=25`, `capture_tls=True`), planner over
  `db`-persisted context, registry of 18 security-test modules (`assess/tests/`: headers, tls,
  disclosure, cors, auth, authorization, methods, redirects, oauth, jwt, idor, xss, ssti, sqli,
  ssrf, graphql, ...). Findings persist only from validated candidates; external-tool
  observations surface only as `candidate` status.
- **Observations**: single normalization/redaction choke point `build_observation`
  (`observations/normalize.py`). `SENSITIVE_HEADERS` includes `set-cookie`/`cookie` (values
  replaced whole with `<REDACTED>`). Closed `OBSERVATION_TYPES` vocabulary.
- **Frontend**: React 19 + Vite 8 (`frontend/`). `src/api.ts` hardcodes API base
  `http://127.0.0.1:8001` (env `VITE_API_URL` is honored but no `.env` is shipped). Pages:
  Scans, NewScan, Reports, Dashboard, ToolHealth, Settings, KnowledgeBase, AIChat,
  Assets, Auth. Component `Phase7Console.tsx`.
- **Reporting**: `reports.py` builders + persisted `Report.json_content`; both shapes carry
  `execution_platform_version: "phase7"` — the Phase 8 report must keep this field and all
  existing keys (Phase 7 regression gate).
- **Workers**: in-process `ScanJobRegistry` thread pool (`app/workers/tasks.py`), cooperative
  cancellation, optional Celery fallback (CELERY_AVAILABLE=False in this env).

## 2. Reusable components for Phase 8 (do not reimplement)

| Need | Reuse |
|---|---|
| Real HTTP to WM runtime | `app/http/client.py` `SafeHttpClient(guard, limits, capture_tls=True)`; stdlib probes pattern in `app/tools/real_probes.py` (bounded body/raw capture) |
| Scope / SSRF guard | `app/core/auth.py::is_target_in_scope` + `engine._scope_guard`; `database/schemas.normalize_target` |
| Observation persistence w/ redaction + fingerprint | `observations/normalize.py::build_observation` (single choke point) |
| Execution trail | `executions.py::execute_tool` adapter/probe dispatch, bounded `ToolExecution`, retry, cancellation, `events.emit_tool` |
| Native checks | `assess/tests/headers.py` (17.1), `assess/tests/tls.py`+`capture_tls` (17.3), `assess/tests/disclosure.py` (17.4) |
| Stage ledger / progress / coverage | `orchestration/stages.py`, `pipeline.py` progress counters, `events.py` |
| Fire-and-forget checkpointing | `workers/tasks.py` registry (same worker, no new runner/engine) |
| Report/regression structure | `pipeline._build_report`, `api/scans.py` report+streaming endpoints |
| Test infra | `conftest.py` (migrate-to-head fixture), localhost real-HTTP fixture pattern from `test_phase7_real_local_scan.py` + `C:\Users\ZEEL\AppData\Local\Temp\opencode\fixture_server.py` |

## 3. Services / APIs / models that must NOT be duplicated

- `Scan`, `Observation`, `Vulnerability`, `FindingValidation`, `FindingObservationLink`,
  `FindingEvidence`, `ToolExecution`, `ToolReadiness`, `ScanStage`, `ScanEvent`, `MLInference`,
  `ToolResult`, `Report`, `ReportExport`, `Asset`, `Project`, `Schedule`(nonexistent) — Phase 8
  adds only `WorldMonitorTarget` (+ optional `WorldMonitorAPIEndpoint`) with its own migration.
- No second assessment engine, no second observation normalizer, no second event system, no
  second worker/runner, no second HTTP client stack.
- `/scans/*`, `/reports/*`, `/tools/*`, `/system/*`, `/auth/*`, `/chat/*` endpoints stay
  verbatim. Phase 8 adds only a new `/world-monitor/*` router (+ optional scan payload key).
- No new `OBSERVATION_TYPE` is needed if cookie data rides inside existing `http_response`
  data; if the `cookie` observation type is added it must be appended to the closed tuple and
  documented (decision below).

## 4. Tests that must remain passing (Phase 7 regression gate)

- `backend/tests/`: 34 files, 252 tests green (incl. `test_imports.py`, `test_root_cors.py`,
  `test_phase7_*.py`, `test_phase6_reporting.py`, `test_scope.py`, `test_authorization.py`).
  Full command: `python -m pytest tests/ -q` from `backend/`.
- Crucially `conftest.py` runs `alembic upgrade head` before the suite: the new migration MUST
  stay in the same linear chain (`2c6e4ab9f71d` → new revision) or the whole suite fails at
  session setup.
- `backend/tests/test_imports.py` asserts CORS default includes `http://localhost:5173`.
- Frontend gates: `tsc --noEmit` and `npm run build` green; smoke suite 77/77 (fixture on
  localhost:80, client `smoke_client.py`).
- Phase 8 additions must not weaken these assertions (no test deletions; extend-only).

## 5. Spec-vs-repo mismatches / assumptions (recorded, not silently resolved)

- **Repo path**: spec says `D:\CyberAgent` with `app/`, `migrations/`, `infra/` at root. Actual:
  `E:\SEMESTER 3\SIH\Security-assesment-of-world-monitor` with `backend/app/`,
  `backend/alembic/`, `backend/tests/`. No `infra/` directory exists anywhere.
- **Kafka**: spec §20 mentions a Kafka-consumer end-to-end scenario with AI-generated fake
  findings. No Kafka code exists in the repo — resolved as N/A (documented in Reality Audit).
- **"Fake findings" audit**: no hardcoded/fabricated findings exist in any runtime path
  (pipeline, reports, API, dashboard). Matches for "SQL Injection / outdated jQuery / CVE"
  are static educational content in `KnowledgeBase.tsx` and `AIChat.tsx` only. Nothing to
  delete; noted in Reality Audit.
- **Env wiring**: README implies `VITE_API_URL`/.env; `src/api.ts:3` hardcodes
  `http://127.0.0.1:8001` and no `frontend/.env.example` is shipped. Plan: keep fallback,
  document.
- **No WM URLs assumed**: no World Monitor base URL may be guessed; the provider derives
  nothing beyond what `WORLD_MONITOR_*` env/config declares + what live probes confirm.
- **CORS**: default origins now include 5173/5174/5175 loopback (already live, tests assert
  5173 present only).
- **Simulation path**: `test_phase4_engine.py` + SSE contract depend on the legacy
  `agents/workflow.orchestrate_scan` simulation path; Phase 7 real path must stay the
  simulation=false route (already the case).

## 5b. Migration strategy (integrated, existing system only)

Inspection outcome: the project already uses Alembic with a **linear 8-revision chain**
(head `2c6e4ab9f71d`), a startup `verify_schema()` that fails loudly and never mutates the
schema, an operator-facing migration command `alembic upgrade head` (already printed by
`verify_schema`'s error and documented), and a migration-verification test suite
(`backend/tests/test_schema.py`) asserting the exact table set, `alembic_version` presence,
and `alembic_version.version_num == "2c6e4ab9f71d"`. `create_all`/`drop_all` appear nowhere in
runtime code; `downgrade()` exists only inside Alembic scripts and is never invoked
automatically.

Phase 8 therefore:
- Adds **one additive migration** in the SAME Alembic chain: `down_revision='2c6e4ab9f71d'`
  → `world_monitor_targets` (+ `world_monitor_api_endpoints`), new tables only, no columns
  altered on existing tables.
- Keeps startup verification exactly as-is (`verify_schema()` → fails loudly with the
  "Run 'alembic upgrade head'" message when the new tables are absent). **No automatic
  upgrade, no downgrade, no `Base.metadata.create_all()`, no schema mutation at startup.**
- Extends the existing verification gate rather than inventing new machinery: bump
  `test_schema.py::HEAD_REVISION` to the new revision id and add the new tables to its
  `EXPECTED_TABLES` assertion; `conftest.py` already migrates to head, so the whole suite
  proves the new revision reproduces the models.
- Documents (in `PHASE_8_IMPLEMENTATION.md`) that the deployment step is the same operator
  command as before: `alembic upgrade head`. Deployment semantics unchanged.

## 6. Phase 8 design decisions (smallest safe increment)

1. **New package** `backend/app/integrations/world_monitor/`:
   - `__init__.py` — module exports.
   - `models.py` — `WorldMonitorProviderStatus` constants (`not_configured`, `checking`,
     `reachable`, `unavailable`, `partially_discovered`, `discovered`, `unsupported`,
     `not_testable`, `blocked`, `gap`); dataclass payloads `HealthResult`, `DiscoveryResult`,
     `WorldMonitorAPIEndpoint` (method, path, security references only). Never `secure/insecure`.
   - `health.py` — `check_health(target, client)` → real GET, bounded, scope-guarded.
   - `discovery.py` — discovery order strictly: (1) base_url root, (2) api base url,
     (3) openapi url, (4) common metadata locations ONLY when the OpenAPI doc is not found
     and presence is provable from live responses (never guessed), (5) frontend-derived API
     references only when evidenced in the UI HTML. Each step records
     `checked|reachable|unavailable|unsupported`.
   - `provider.py` — `WorldMonitorProvider` orchestrates health → discovery → inventory;
     companion `get_api_inventory(openapi_json)` normalizes paths to
     `WorldMonitorAPIEndpoint` rows + `api_route` observations.
   - `normalizers.py` — WM → `build_observation` kwargs (source `http_client`), and OpenAPI
     → `api_route` observation data (summary/security schemes, never secrets).
2. **Config**: `WORLD_MONITOR_BASE_URL`, `WORLD_MONITOR_API_BASE_URL`,
   `WORLD_MONITOR_OPENAPI_URL` env keys in `backend/app/config.py` (new settings fields) +
   `backend/.env.example`.
3. **Model + migration**: `WorldMonitorTarget` (project_id FK, name, base_url, api_base_url,
   openapi urls, status, checked_at, health_json, discovery_json, fingerprint, timestamps),
   nullable/additive, new alembic revision `down_revision='2c6e4ab9f71d'`. `WorldMonitorAPIEndpoint`
   only if inventory must be joinable server-side (decision: add it — API inventory is a
   first-class Phase 8 artifact and keeps `project_id` isolation queries trivial).
4. **Scope/SSRF**: every URL fetched validates against the project scope via
   `is_target_in_scope`/`host_of` (engine `_scope_guard` style). Requests use the bounded
   `SafeHttpClient`; no redirects outside scope; only http/https schemes.
5. **Pipeline integration**: new built-in probe tool `world_monitor_discovery` placed in
   `TOOL_TO_STAGE[TARGET_NORMALIZATION]` (default enabled). `executions.py` dispatch maps it to
   the provider; a run skips honestly (`status=skipped`, reason "world monitor not configured")
   when no in-scope WM target exists. It persists real `http_response`/`api_route`/`header`
   observations only. No new runner/engine; same worker, events, coverage. `config`
   `world_monitor: {target_id}` selects the target when unambiguous; otherwise the pipeline
   uses the first in-scope `not_configured/unavailable`-passed target (or skips honestly).
6. **Cookie attributes (17.2)**: `normalize.redact_headers` drops `Set-Cookie` values
   wholesale, so capture happens at capture time in `real_probes.http_probe` + engine client:
   parse `Set-Cookie` → list of `{name, http_only, secure, same_site, path_flags}` with values
   NEVER persisted, stored under `data_json["cookies"]` (non-sensitive key). New native test
   `cookies.security_attributes` (passive) appended to the registry; planner picks it up.
7. **Checks 17.1–17.4 mapping**: 17.1 headers → existing `http.security_headers`;
   17.2 cookies → new `cookies.security_attributes`; 17.3 TLS → existing `tls` test
   over `certificate` observations (`capture_tls=True` already); 17.4 info disclosure →
   existing `disclosure` test + OpenAPI-described endpoints as additional candidate subjects.
   Every finding remains observation-derived (evidence chain intact).
8. **New API router** `backend/app/api/world_monitor.py` (registered in `main.py`):
   `POST/GET /world-monitor/targets`, `GET/DELETE /world-monitor/targets/{id}`,
   `POST /world-monitor/targets/{id}/check`, `POST /world-monitor/targets/{id}/discover`,
   `GET /world-monitor/targets/{id}/inventory`. Auth + project ownership server-side; no
   cross-project access.
9. **Reporting continuity**: `execution_platform_version` stays `"phase7"`; WM artifacts
   surface as observations + optional `world_monitor` block in the report JSON (additive key),
   markdown gains a short WM section only when a target was checked.
10. **AI**: unchanged `advisory_only` (`model_name=None`).
11. **Frontend (targeted)**: NewScan optional WM target picker (in-scope targets), small
    WorldMonitor section in `Phase7Console.tsx` showing target status / discovery/skip events,
    plus a `WorldMonitorTargets` page only if Scans/NewScan proves insufficient (default: not
    needed). No new dependencies.
12. **Tests (extend-only, no mocks of the real path)**: provider/health/discovery/inventory
    unit tests against a localhost real-HTTP fixture; `tests/test_phase8_world_monitor_real.py`
    e2e (register target → scan → assert real observations/findings); migration test
    (upgrade head reaches new revision); SSRF/scope tests (out-of-scope host → blocked/skip);
    cookie-attribute redaction test (values never persisted); frontend acceptance notes.

## 7. Smallest safe implementation sequence (each step ends green)

1. Config env keys + `.env.example`; unit-test settings. → run `pytest tests/test_imports.py`.
2. `WorldMonitorTarget` + `WorldMonitorAPIEndpoint` models + alembic migration
   (`down_revision='2c6e4ab9f71d'`); bump `tests/test_schema.py::HEAD_REVISION` + `EXPECTED_TABLES`;
   migrate the local DB (`alembic upgrade head`) and re-verify app boots (startup `verify_schema`
   unchanged — fails loudly pre-migration, never mutates). → `pytest tests/test_schema.py`
   plus full `pytest` once the new suite passes at step 7.
3. `world_monitor` package: health → discovery → inventory + normalizers, with real-HTTP
   unit tests against the localhost fixture (extend existing fixture needs).
4. Router `/world-monitor/*` + auth/ownership/SSRF tests.
5. Cookie-attribute capture in `real_probes.http_probe` + engine client + new
   `cookies.security_attributes` test (lock by the redaction test). Full `pytest`.
6. `world_monitor_discovery` probe tool in stages/executions + pipeline wiring (honest skip
   when unconfigured). Full `pytest`.
7. `test_phase8_world_monitor_real.py` e2e (fixture-based WM runtime). Full `pytest`
   (expect 252 + new, all green).
8. Frontend: WM picker + Phase7Console section; `tsc` + `build`.
9. Restart dev servers, run a real scan against the fixture, verify events/report.
10. Docs: `PHASE_8_IMPLEMENTATION.md`, `PHASE_8_REALITY_AUDIT.md`, `PHASE_8_ARCHITECTURE.md`;
    report format section with counts (regression PASS, tests totals, WM IMPLEMENTED items,
    hardcoded findings = 0, fake endpoints = 0, evidence-less findings = 0).