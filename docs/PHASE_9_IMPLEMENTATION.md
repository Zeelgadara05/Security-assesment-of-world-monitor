# Phase 9 — Implementation (& the §49/§50 acceptance surface)

**Date:** 2026-09-22
**Read with:** `PHASE_9_ARCHITECTURE.md` (intended design) and
`PHASE_9_REALITY_AUDIT.md` (independently re-verified claims). This document
records what actually shipped for the Capstone Phase, file by file, and how to
prove each surface.

## 1. What Phase 9 delivers to an operator

Phase 9 completes the single canonical evidence chain — *real observation →
persisted evidence → detection → verification → finding → report* — and makes
every link visible and servable from the workspaces an operator actually uses.

The chain is **the only** source of truth. Nothing is invented: no guessed
endpoints, no fabricated counters, no fabricated coverage, no secure/insecure
vocabulary. A finding only ever exists if a real `Observation` row was
persisted and fed the Phase 5 engine; an asset only ever exists if an
observation surfaced it.

## 2. Shipped components

### 2.1 The granular evidence-chain event stream
`backend/app/orchestration/events.py` grew typed emitters that fire **only after
a real row was flushed**, each carrying the persisted ids the frontend needs to
drill down:

| Event type | Emitted after | Payload carries |
| --- | --- | --- |
| `observation.created` | `Observation` persisted | `observation_id`, `kind`, `subject`, `tool_name` |
| `asset.discovered` | `Asset` row persisted | `asset_id`, `type`, `value` |
| `finding.candidate` | candidate created | `finding_id`, `rule_id` |
| `finding.verified` | lifecycle `verified` | `finding_id`, `status` |

Unknown/unregistered event types are rejected before any row is written
(no free-form buffer).

### 2.2 The asset graph (host → endpoint hierarchy)
`backend/app/orchestration/pipeline.py` gained `_populate_asset_graph`, which
links every persisted observation onto a **deduplicated** `Asset` row:

* one deduplicated **host** asset per bare host subject, and one **endpoint**
  asset per `scheme://…` subject;
* the endpoint row carries `parent_asset_id → host` (a real parent edge);
* every observation gains `observations.asset_id` pointing at its asset;
* observability: the new `type` metadata (`source: "observation:{kind}"`, the
  asset's `source`) records exactly how each asset was discovered.

The model `parents`/`children` self-referential edges were corrected to a true
adjacency list (`remote_side` on the parent backref) so the RDBMS graph is
honest: a host lists its real endpoints, never the reverse.

### 2.3 Six-stage operator workspace (scan detail tabs)
`GET /scans/{id}` now exposes overview, live console (typed SSE events),
observations, findings, assets and comparisons — every one ownership-scoped.

### 2.4 5-step New Scan wizard
`NewScan.tsx` leads an operator through: **1)** target entry, **2)** scope &
assessment type, **3)** tool/capability selection with honest preflight
readiness, **4)** profile & severity configuration, **5)** review & authorize.
Each step is driven by real capability data; nothing is pre-invented.

### 2.5 World Monitor operator page
`WorldMonitor.tsx` gives the operator the configured-deployment view: register
targets, run health checks, trigger discovery, inspect inventories, and delete
stale targets — all against the persisted world-monitor rows, with honest
status vocabulary (`up`/`down`/`degraded`, never `secure/insecure`).

### 2.6 Findings triage + verdict history workspace
The Findings workspace visualises the operator timeline: candidate → verified →
accept/triage actions, each appended immutably to `FindingStatusHistory` and
replayed by `GET /findings/{id}`. Every verdict is actor + timestamped.

### 2.7 Reports + deterministic exports
Reports expose HTML and a pure-stdlib PDF written from the same section model
as JSON/Markdown (`backend/app/reporting/pdf_writer.py`,
`backend/app/reporting/html_renderer.py`), each `ReportExport` recording the
SHA-256 content hash and the registry/config fingerprints so a regenerated
report is reproducible byte-for-byte.

### 2.8 Dashboard aggregate (§50 dashboard evidence chain)
`GET /dashboard/summary` derives every metric from persisted rows owned by the
caller — scans, observations, findings lifecycle buckets, asset graph, coverage
trend — never from sample figuresfixtures.

## 3. Concrete file surface

| Concern | Files |
| --- | --- |
| Granular events | `backend/app/orchestration/events.py` |
| Asset graph | `backend/app/orchestration/pipeline.py` (`_populate_asset_graph`), `backend/database/models.py` (`Asset`) |
| API | `backend/app/api/scans.py` (assets/observations/typed-events endpoints), `backend/app/api/findings.py` (triage + history), `backend/app/api/reports.py`, `backend/app/api/dashboard.py` |
| Exports | `backend/app/reporting/{pdf_writer,html_renderer,export}.py` |
| Frontend | `frontend/src/pages/{NewScan,Scans,Findings,Reports,WorldMonitor}.tsx`, `frontend/src/App.tsx` |
| Tests | `backend/tests/test_phase9_{granular_events,dashboard,report_exports}.py` |

## 4. Verifying this surface (the §49/§50 acceptance run)

```
cd backend
venv\Scripts\python.exe -X dev -W ignore -m pytest tests\test_phase9_granular_events.py \
        tests\test_phase9_dashboard.py tests\test_phase9_report_exports.py -q
```

Expected: 9 passed. Full suite: **333 passed** (measured 2026-09-22), an
operator notebook can greenline every Phase 9 surface from these three files
alone.

## 5. Honest notes

* The sim path (`SIMULATION_MODE=true`) remains intact as the deterministic
  preflight used by tests and the SSE-simulated UI; Phase 9 extends the real
  path and never rewrites the legacy `Scan.status` coexistence model.
* The `docs/PHASE_9_ARCHITECTURE.md` "MISSING" table rows are now all shipped
  (asset graph, granular events, HTML/PDF exports, dashboard aggregate,
  findings triage workspace, World Monitor page).
