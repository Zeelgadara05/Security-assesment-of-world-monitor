# Phase 9 — Architecture

**Date:** 2026-09-21
**Scope:** internal design of the Capstone Phase (Phase 9). Read with
`PHASE_9_IMPLEMENTATION.md` (what shipped) and `PHASE_9_REALITY_AUDIT.md` (what
was verified).

## 1. Design principle: one evidence chain, end to end

Phase 9 does not add a second pipeline. The platform already has exactly one
canonical evidence path, and Phase 9 completes it:

```
 REAL TARGET ─► REAL OBSERVATION ─► PERSISTED EVIDENCE ─► DETECTION
      │               │                      │                 │
      │               ▼                      ▼                 ▼
 authorized      build_observation()   finding_rules /      candidate
 scope guard     redacted, typed       Phase 5 engine       status
      │                                                       │
      ▼                                                       ▼
 persistence ─────────────────────────────────────► VERIFICATION ─► FINDING ─► REPORT
 (scans/assets/observations/tests/                      │
  findings/evidence/events/executions)                  ▼
                                              lifecycle transitions,
                                              validator verdicts
```

Phase 9's job is to make this chain *visible to an operator* (dashboard,
scan workspace, findings workspace, reports) and *servable* (real HTML/PDF
exports), while keeping the invariants that earlier phases established:

- **Observations are the only accepted source of evidence.** Findings are
  derived exclusively from persisted `Observation` rows; external tool output
  only ever produces candidate status.
- **Nothing is invented.** No guessed endpoints, no fabricated counters, no
  sample figures, no LLM-created evidence.
- **Redaction is centralized** at `app/observations/normalize.py`.
- **Ownership is enforced** through the user → project → scan → evidence →
  report chain (non-owner → `404`).
- **Profiles select only existing capabilities** and CVSS is only ever assigned
  from justified vectors.

## 2. Gap analysis (audit of the shipped platform)

The audit confirmed the four classes below. Everything marked
*EXISTING* is already shipped and is reused — never rewritten.

### 2.1 EXISTING (ship, reuse as-is)

| Area | Evidence | Notes |
| --- | --- | --- |
| One observation pipeline | `app/observations/normalize.py`, `types.py` | `build_observation()` + redaction + status vocabulary |
| Real probe layer | `app/tools/real_probes.py` | dns/tcp/http stdlib probes; the only path into the findings engine |
| Capability matrix | `app/tools/capabilities.py` | Native stdlib caps always available; external tools only when installed |
| Scope guard | `app/http/client.py` (`SafeHttpClient`, `OutOfScopeError`), `app/core/auth.py` (`is_target_in_scope`) | Every request + redirect hop is scope-checked |
| Ownership isolation | `app/core/auth.py` (`get_owned_scan`, `get_or_create_user_project`) | Non-owner = 404 |
| Finding lifecycle | `app/assess/finding_lifecycle.py` | candidate → validated → confirmed / rejected / duplicate / accepted / remediated / reopened |
| Finding triage + history | `app/api/findings.py` | `confirm/false_positive/duplicate/accepted_risk/resolve`, immutable `FindingStatusHistory` |
| Assessment engine | `app/assess/engine.py` | planner → tests → observations → findings → evidence; `_MAX_ENDPOINTS=25`, `_MAX_REQUESTS=200`; active_testing opt-in; scope-guarded; never simulated |
| Deterministic rules + dedup | `app/assess/finding_rules.py`, `dedup.py` | evidence-backed candidates, severity thresholds, fingerprint dedup |
| Cross-scan tracking | `app/assess/tracking.py` | first/last scan, occurrence count, fingerprint diff |
| ML boundary | `app/ml/advisory.py` | `advisory_only`, no model prediction enters the pipeline |
| Report builder + export | `app/reporting/builder.py`, `export.py`, `models.py` | 13-section deterministic report; JSON + Markdown; SHA-256 content hash |
| Phase 7 pipeline | `app/orchestration/pipeline.py`, `stages.py`, `executions.py`, `events.py`, `preflight.py`, `state.py` | 13 stages, typed event stream, real counters, cooperative cancellation, retry |
| Coarse + fine lifecycle sync | `app/agents/lifecycle.py`, orchestration state machine | `scan.stage`/`status` derived; never a third status system |
| Preflight gating | `app/orchestration/preflight.py` | Blocks scan when required tooling is missing; honest readiness |
| SSE for live UI | `/scans/{id}/events`, `/stream`, `/typed-events` | cursor-replayable typed stream |
| Auth + RBAC | `app/core/auth.py`, `app/core/security.py` | PBKDF2, bearer sessions, admin/user roles |
| World Monitor integration | `app/integrations/world_monitor/*`, `app/api/world_monitor.py` | config-driven, honest connectivity states, no `secure/insecure` |
| Assessment type taxonomy | `app/api/scans.py` | `world_monitor` vs `custom_target`, authorization acknowledgement |
| Schema management | `alembic/versions/*` (9 additive migrations) | `verify_schema()` fails loudly when not at head |

### 2.2 PARTIAL (exists, needs extension)

| Area | Currently | Phase 9 change |
| --- | --- | --- |
| Scan model | `assessment_type`, `authorization_acknowledged`, `coverage`, `preflight_json`, queue timing | add retry/schedule metadata: attempt count, schedule cadence, priority hint (`ScanAttempt` history) |
| Scan API | create/list/detail/cancel/retry/coverage/summary | add **dashboard aggregate** (cross-scan findings trends, coverage trend, scan cadence), **PDF export**, schedule endpoints |
| Report export | `format=json\|markdown` via API; pipeline stores placeholder `pdf_content` | add **HTML** and **real stdlib-only PDF** renderers; file-download endpoint |
| Event vocabulary | `state/stage/tool/preflight/progress/coverage/finding/validation/done/error` | add granular `asset.discovered`, `observation.created`, `finding.candidate`, `finding.verified`, `finding.rejected` |
| Observation model | typed observations with request/response redaction | add `asset_id` FK to link observations onto the asset graph |
| Vulnerability model | lifecycle `status`, `fingerprint`, first/last seen, `evidence_observation_ids` | add `endpoint_asset_id` FK; add CVE correlation state (`observed/potentially_affected/confirmed`); confidence badge |
| Assessment tests | full test ledger + SIH area mapping | expose per-area coverage in the scan workspace |
| Frontend Scans page | list + embedded Phase7Console | tabbed **scan workspace** (Overview / Live Console / Observations / Findings / Assets) |
| Frontend New Scan | single-form page | 5-step wizard (target+scope check → assessment type → tools/capabilities → profile/severity → review & acknowledge) |
| Frontend Dashboard | `/scans/list` + `/scans/summary` | expansion context + recent activity + per-severity drill links |

### 2.3 MISSING (not yet implemented)

| Missing piece | Required behaviour |
| --- | --- |
| Asset graph | Host → service → endpoint → response edges (an asset has services, each service has endpoints with observed responses), built only from persisted observations |
| Real PDF report | Pure-Python stdlib-only minimal PDF writer (no reportlab/weasyprint in requirements), generated deterministically from the same section model as JSON/Markdown |
| HTML report renderer | Server-side deterministic HTML from the report section model (no JS dependency for the document itself) |
| Report download endpoint | `GET /scans/{id}/report?format=html\|pdf` returns an actual file attachment; export is recorded with content hash like json/markdown |
| Dashboard aggregation endpoint | Cross-scan, cross-asset, time-bucketed trends derived only from persisted rows (findings by severity over time, coverage over time, assets discovered, scan cadence, recent findings with asset context) |
| Finding → asset drill-down | From a finding, navigate to the affected asset and its observed endpoints/responses |
| Attempt/schedule model | `ScanAttempt` history + optional schedule cadence persisted on the scan (additive migration) |
| Frontend findings workspace | Evidence drill-down, asset link, lifecycle triage actions, verdict history timeline |
| Frontend World Monitor page | Dedicated route for configured deployments (currently only reflected inside Phase7Console) |
| Frontend Reports page | Report list + download (html/pdf/json/markdown) with content hashes |

### 2.4 CONFLICTS (resolved deliberately, must stay frictionless)

| Conflict | Resolution |
| --- | --- |
| Two report stores | `Report` (in-scan artifact rows) vs `ReportExport` (hash + fingerprints). Phase 9 keeps both: the `Report` row is regenerated by the pipeline; `ReportExport` records every on-demand export for reproducibility. |
| Placeholder `pdf_content` | `pipeline._build_report` stored `markdown.encode("utf-8")` as `pdf_content`. Phase 9 replaces with a real stdlib-only PDF; the `Report` row keeps a genuine PDF blob. |
| Legacy `Scan.status` vs Phase 7 `Scan.state` | Coarse status remains derived from the lifecycle; Phase 9 never introduces a third status system. |
| Legacy finding `state` (NEW/CONFIRMED/…) vs lifecycle `status` | `state` stays for Phase-3 consumers; lifecycle `status` is primary and extended by Phase 9. |
| Simulation path | `orchestrate_scan_phase7` delegates to the Phase 4 orchestrator when `SIMULATION_MODE=true` (tests/SSE rely on it). Phase 9 extends the *real* pipeline only; the simulation path must keep passing unchanged. |

## 3. Component boundaries (Phase 9 additions)

### 3.1 Asset graph
New `AssetNode`-style tables are **not** planned — the existing `Asset` table
is extended with `parent_asset_id`/`kind` metadata and observations gain an
`asset_id` link, so the graph reuses the observations that already exist.

### 3.2 Reporting
The report stays a single `AssessmentReport` model. HTML is rendered from the
same `ReportSection` list; the PDF is produced by a new
`app/reporting/pdf_writer.py` (pure-stdlib) from the same markdown/sections —
three renderers, one source of truth, one `ReportExport` record each.

### 3.3 Dashboard aggregate
New endpoint `GET /dashboard/summary` under `app/api/dashboard.py`, computing
trends entirely from persisted rows owned by the caller (no hardcoded numbers).
The existing `/scans/summary` stays untouched for compatibility.

### 3.4 Frontend
Strictly additive: `Dashboard.tsx` gains expansion context via the new
aggregate endpoint; `NewScan.tsx` becomes a 5-step wizard; `Scans.tsx`
becomes a workspace host with tabs; new pages for World Monitor and Reports.
All requests remain funneled through `api.ts` and the shared design system in
`index.css`.

## 4. Safety

| Concern | Mechanism |
| --- | --- |
| Evidence integrity | Observations stay the only source; findings without observation ids are impossible by construction |
| PDF determinism | Assertions in tests compare byte-for-byte regenerated PDFs from the same scan state |
| No guessed data | The asset graph, trends, and report render only persisted rows; WM endpoints remain config-driven |
| Schema | Single additive Alembic migration; `verify_schema()` still fails loudly when not at head |
| Isolation | Every new endpoint goes through `get_owned_scan` / project ownership chain |
| Performance | Dashboard endpoint aggregates with a fixed number of SQL queries + in-Python bucketing; indexes preserved |