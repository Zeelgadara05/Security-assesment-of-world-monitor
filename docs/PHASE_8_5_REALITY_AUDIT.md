# Phase 8.5 — Reality Audit

Audit of the repository against the Phase 8.5 product-alignment directive,
performed **before** any Phase 8.5 code change. Scope: does the running product
honestly represent its purpose (World Monitor assessment + custom authorized
targets on one real engine), and what remains to reach the directive?

- Repository: `E:\SEMESTER 3\SIH\Security-assesment-of-world-monitor`
- Branch: `feature/fix-001`
- Baseline: Phase 7 execution platform + Phase 8 World Monitor integration, full
  backend suite green (301 tests).
- Method: source inspection of `backend/app/**`, `backend/database/models.py`,
  `backend/alembic/versions/**`, `frontend/src/**`; string searches for
  fabricated/demo content.

> Note: the directive referenced `D:\CyberAgent`. That path does not exist on
> this machine; the actual working tree is the path above. Confirmed with the
> operator before proceeding.

## 1. What already satisfies the directive

| Requirement | Evidence |
|---|---|
| One real assessment engine (not two) | `backend/app/assess/` (planner, registry, applicability, dedup, evidence, severity) |
| Evidence-first pipeline | Observation -> Candidate -> Validation -> Finding -> Evidence -> Report; `app/assess/evidence.py`, `app/reporting/evidence_renderer.py` |
| No fabricated runtime findings | Findings derive from persisted observations/tests; candidates vs confirmed split in `app/reporting/builder.py:149-154` |
| Coverage describes the assessment, not security | `app/reporting/coverage_renderer.py`, coverage statement in `builder.py:124` |
| Execution state machine + honest gaps | `app/agents/lifecycle.py`, `Scan.state`, `completed_with_gaps` |
| World Monitor as a real, authorized target | `app/api/world_monitor.py`: `/targets` CRUD, `/check`, `/discover`, `/inventory`; persisted raw `health_json`/`discovery_json` |
| WM status vocabulary (no verdict) | `not_configured | checking | reachable | unavailable | partially_discovered | discovered`; `database/models.py` |
| WM discovery is dynamic / config-driven | `WorldMonitorTargetCreate` requires explicit `base_url`; optional same-host `api_base_url`/`openapi_url` (`world_monitor.py:54-73,167-173`); no hardcoded endpoints in `app/` |
| Scope + SSRF protections | `_target_scope_guard` (`world_monitor.py:89-111`), `app/assess/engine._scope_guard`, `app/http/client.py`, `is_target_in_scope` |
| Alembic migrations (incl. Phase 8) | `alembic/versions/` has 8 revisions incl. `3d7f5bc81a02_phase8_world_monitor.py`; no `create_all` as migration substitute |
| ML is advisory, not authoritative | `app/ml/advisory.py` (coverage-gap advisory only) |
| Forbidden AI-slop strings absent from runtime | `AI-powered`, `threat intelligence`, `neural`, `autonomous`, `copilot`, `magic`, `intelligent`, `smart scan` appear only in `docs/` and test fixtures |

## 2. Gaps against the directive

| # | Gap | Location / evidence |
|---|---|---|
| G1 | No assessment-type discriminator (`world_monitor` vs `custom_target`) | search `assessment_type` -> 0 hits; `ScanCreate` has only free-form `profile` + optional `world_monitor` dict (`scans.py:29-55`) |
| G2 | No persisted authorization acknowledgement | search `acknowledg` -> 0 hits; `NewScan.tsx` has only an active-testing opt-in |
| G3 | No explicit WM-vs-custom choice in the creation UI | `NewScan.tsx` is a single form; WM is an optional side panel (`~539-603`) |
| G4 | No SIH26163 security-area mapping or area-level coverage | engine categories are rule-level (`auth, authorization, cookies, cors, disclosure, graphql, headers, idor, jwt, methods, oauth, redirects, sqli, ssrf, ssti, tls, xss`); no mapping to the 7 SIH areas |
| G5 | No dedicated Findings page / cross-assessment findings list | nav has no Findings entry; `/findings` API is per-finding only (`triage`, `get`, `evidence`) |
| G6 | Report lacks SIH-area section, Observed/Validated/Inferred labels, and PoC / steps-to-reproduce | `builder.py:130-176` (13 sections, none SIH/area or PoC) |
| G7 | ML advisory not labelled as such in UI/report | advisory exists but no explicit `ML Advisory` label/no-authority statement surfaced |
| G8 | Nav IA does not match directive (Overview, Assessments, Findings, Reports, Assets, Tools, Settings) | `DashboardLayout.tsx:36-61`: has New Assessment / Assessments / Assets / Reports / Assessment Assistant / Tool Health / Knowledge Base / Settings |
| G9 | Brand tagline still reads "Scan Platform" | `DashboardLayout.tsx:217`, `Auth.tsx:98` |
| G10 | Cycle docs not yet authored | `docs/PHASE_8_5_{IMPLEMENTATION,ARCHITECTURE}.md` absent (this file is the audit) |

## 3. Domain invariants that MUST be preserved by Phase 8.5

- Persisted-tool SSE replay contract: `/scans/{id}` preloads tools AND `stream_scan_events`
  replays every persisted `ToolResult` (`tests/test_phase4_engine.py:134,406`).
  The frontend dedupes by name; do not "fix" this by removing replay.
- Evidence invariant: no confirmed finding without verifiable evidence
  (`tests/test_phase7_real_local_scan.py:163`).
- Server-side scope enforcement is the real authorization control; the UI
  acknowledgement is an audit record, never the enforcement mechanism.
- Phase 7 `execution_platform_version = "phase7"` and the 13-section report
  structure remain stable; Phase 8.5 adds, it does not rename/remove.
- No `Base.metadata.create_all()` as a migration substitute; no auto-downgrade.

## 4. Verdict

Phase 8.5 is a **product-alignment + information-architecture + SIH-mapping**
cycle on top of an already-real engine, not a rebuild. The engine, WM
integration, evidence model, scope/SSRF guards, migrations and ML advisory are
in place. The concrete remaining work is G1-G10, sequenced in
`docs/PHASE_8_5_IMPLEMENTATION.md` (Steps 1-15).

## 5. Post-implementation verification (Step 15)

Everything below was re-checked after the Phase 8.5 changes landed. The cycle is
complete and the no-fabrication property still holds.

### 5.1 Gap closure

| # | Status | Evidence |
|---|---|---|
| G1 | Closed | `Scan.assessment_type` + `_resolve_assessment_type`; migration `9a4b7c2e5f10` |
| G2 | Closed | `Scan.authorization_acknowledged{,_at}`; wizard requires the acknowledgement |
| G3 | Closed | `NewScan.tsx` three-step wizard: World Monitor vs custom target |
| G4 | Closed | `app/assess/sih.py`; `assessment.sih`; SIH panel on the assessment detail |
| G5 | Closed | `GET /findings` + `frontend/src/pages/Findings.tsx` + nav entry |
| G6 | Closed | report `sih_coverage` section, `provenance` (validated/observed), existing PoC block |
| G7 | Closed | "ML Advisory (inferred — not a finding)" label; Settings states no model/partner API |
| G8 | Closed | `DashboardLayout.tsx` nav: Overview, Assessments, Findings, Reports, Assets, Tools, Assistant, Settings |
| G9 | Closed | taglines read "Assessment Platform" (`DashboardLayout.tsx`, `Auth.tsx`) |
| G10 | Closed | `docs/PHASE_8_5_{IMPLEMENTATION,ARCHITECTURE}.md` authored |

### 5.2 No fabricated content in runtime code

- `frontend/src/**` contains no banned AI-slop strings; only engineering
  placeholders (`example.com`) and explicit "never faked" statements remain.
- `backend/app/**` had three residual strings; two were fixed
  (`main.py` OpenAPI description, `chat.py` docstring). The remaining match in
  `app/assess/tests/__init__.py` is the legitimate phrase "import-time magic".
- Runtime findings still derive only from persisted observations/tests: the
  real, unstubbed local-fixture pipeline (`test_phase7_real_local_scan.py`)
  asserts every finding cites persisted observation ids and every confirmed
  finding carries a confirmed validator verdict.

### 5.3 Invariants intact

- Persisted-tool SSE replay, the evidence invariant, the server-side scope
  guard, `execution_platform_version="phase7"`, the 13-section report structure,
  deterministic reports, and additive-only migrations all remain.
- Full backend suite: **322 passed, 0 failed** (from 301 at the Phase 8
  baseline). Frontend `tsc` + Vite build green.

