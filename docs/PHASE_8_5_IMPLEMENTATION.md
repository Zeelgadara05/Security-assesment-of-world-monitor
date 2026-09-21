# Phase 8.5 — Implementation

Product-alignment pass that makes the platform state its real purpose — World
Monitor (SIH26163) assessment plus custom authorized targets, on one engine —
and expose that honestly through the API and UI. This is an alignment cycle over
the Phase 7 execution platform; no second engine and no fabricated data were
introduced.

- Repository: `E:\SEMESTER 3\SIH\Security-assesment-of-world-monitor`
- Branch: `feature/fix-001`
- Precondition: Phase 8 World Monitor integration, green baseline.
- Result: full backend suite **322 passed**; frontend `tsc` + Vite build green.

## 1. Assessment taxonomy (which path produced this run)

A run is either a **World Monitor** assessment or a **Custom authorized target**
assessment; both execute the same engine.

- Model (`backend/database/models.py`): `Scan.assessment_type` (`world_monitor` |
  `custom_target`), `Scan.authorization_acknowledged` (bool),
  `Scan.authorization_acknowledged_at` (datetime).
- Migration `backend/alembic/versions/9a4b7c2e5f10_phase8_5_assessment_type.py`
  (additive; backfills `custom_target`, promotes rows whose `scan_config`
  referenced `world_monitor`). Head revision is pinned in
  `backend/tests/test_schema.py`.
- API (`backend/app/api/scans.py`): `ASSESSMENT_TYPES`, `ScanCreate` gains
  `assessment_type` + `authorization_acknowledged`, `_resolve_assessment_type`
  validates the path and enforces ownership of a World Monitor target. The
  acknowledgement requirement applies **only when `assessment_type` is set** so
  legacy clients are unaffected. `assessment_type` is serialized on create, list,
  details, coverage and `get_scan`.
- Tests: `backend/tests/test_phase8_5_assessment_taxonomy.py`.

## 2. SIH26163 security-area mapping

`backend/app/assess/sih.py` maps the engine's rule-level categories onto the
seven SIH areas and derives coverage from the **persisted assessment-test
ledger only**:

| Area | Categories |
|---|---|
| Authentication & Session Management | auth, authentication, session, cookies, jwt, oauth, csrf |
| Authorization & Access Control | authorization, idor, bola, access_control |
| Input Validation & Data Handling | sqli, ssti, xss, redirects, injection, command_injection, xxe, ssrf |
| API Security | api_security, graphql, methods, cors, ssrf |
| Client-Side Security | xss, cors, csrf, headers |
| Secure Communication (TLS) | tls, headers |
| Data Protection & Privacy | disclosure, privacy, data_protection |

`coverage_by_area(tests)` returns, per area: raw tallies, `coverage_percent`
(`executed / applicable`), and a status of `covered` | `partial` |
`not_assessed`. An area with no applicable tests is reported as
`not_assessed` with a `null` percentage — never `0%` masquerading as a result.
Unmapped categories are surfaced explicitly.

- Exposed on the assessment detail endpoint as `assessment.sih`.
- Tests: `backend/tests/test_phase8_5_sih_areas.py`.

## 3. Cross-assessment findings

`GET /findings` (`backend/app/api/findings.py`) lists findings across every
assessment the caller owns, filterable by `severity`, `status`, `category`,
`sih_area` and `assessment_id` with `limit`/`offset`. Each row carries its
`assessment_type` and mapped `sih_areas`. Ownership is enforced through the
scan → project → user join; an unknown `sih_area` is a `422`.

- Tests: `backend/tests/test_phase8_5_findings_list.py`.

## 4. Report additions

`backend/app/reporting/builder.py` now adds:

- a **SIH26163 Security-Area Coverage** section rendered from `coverage_by_area`;
- **finding provenance** — `validated` (passed a deterministic validator) vs
  `observed` (real, evidence-backed candidate) — on every finding, in JSON and
  Markdown (`backend/app/reporting/finding_renderer.py`);
- an explicit **ML Advisory (inferred — not a finding)** label in the execution
  ledger, alongside the existing PoC block (already present) and the
  Observed/Validated legend in the executive summary.

The pre-existing 13 sections and `assessment_version="phase6"` /
`execution_platform_version="phase7"` contracts are unchanged; the SIH section is
additive.

- Tests: `backend/tests/test_phase8_5_report_sih.py`.

## 5. Frontend

- **IA / navigation** (`frontend/src/layouts/DashboardLayout.tsx`,
  `frontend/src/App.tsx`): Operations → Overview, Assessments, Findings, Reports;
  Inventory → Assets, Tools; Assistant → Assessment Assistant, Knowledge Base;
  Workspace → Settings. A primary `New Assessment` call-to-action leads the nav.
- **Findings page** (`frontend/src/pages/Findings.tsx`): severity tiles, filters
  (severity, lifecycle status, SIH area), a findings table and a detail drawer
  that fetches `/findings/{id}` and shows CVSS, remediation, validation reason,
  PoC and evidence.
- **New Assessment wizard** (`frontend/src/pages/NewScan.tsx`): a three-step flow
  (Path → Configure → Authorize) choosing a World Monitor deployment or a custom
  authorized target, configuring the tool profile, and requiring an explicit
  authorization acknowledgement before launch. Both paths POST to the same
  `/scans` endpoint.
- **Assessment detail** (`frontend/src/pages/Scans.tsx`): a SIH26163 security-area
  coverage panel (per-area status, executed/applicable, honest "not assessed"),
  alongside the 13-stage lifecycle, typed SSE console, tool pipeline and findings.
- **Honest-UX sweep**: user-visible copy uses Assessment terminology and the
  Settings page no longer shows placeholder AI provider key inputs.

## 6. Verification

- `backend/venv/Scripts/python.exe -m pytest` — **322 passed**.
- `frontend/`: `npm run build` (tsc + Vite) — green.
- Real local fixture end-to-end (13-stage pipeline, no stubs) extended to assert
  SIH-area coverage and finding provenance in the generated report:
  `backend/tests/test_phase7_real_local_scan.py`.
