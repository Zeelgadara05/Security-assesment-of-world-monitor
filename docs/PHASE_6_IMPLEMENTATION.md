# Phase 6 — Evidence-Based Security Reporting, Finding Lifecycle & Assessment Completeness

**Date:** 2026-09-20
**Repo:** `D:\CyberAgent`
**Phase:** Deterministic evidence capture, a persisted finding lifecycle, honest
assessment-status/completeness classification, and a stable report export — built
entirely on the Phase 5 assessment engine.

## Intent

Phase 5 established that *a finding requires observation + applicable test +
executed + deterministic validator + evidence*. Phase 6 makes that contract
auditable and exportable:

- **Reportable finding = confirmed.** Only findings that survived the full chain
  (and are `confirmed`) may be presented as vulnerabilities. External tool output
  enters as `candidate` and is never auto-promoted.
- **Lifecycle is a persisted state machine.** `candidate ≠ vulnerability`; every
  transition is validated against a fixed graph and appended immutably to
  `finding_status_history`.
- **Evidence is hashable and bounded.** Stored payloads carry consistency hashes
  and bounded-capture metadata so accidental mutation is detectable in the report.
- **CVSS is computed, never claimed.** Score comes from the v3.1 vector via NIST
  formulas; no vector ⇒ null score.
- **Assessment status describes the assessment, not the target.** Coverage %,
  `completed_with_gaps`, `partial`/`minimal`/`unknown` — never "you are secure".

## New modules

| Module | Responsibility |
|--------|----------------|
| `app/assess/finding_lifecycle.py` | Status constants, transition graph, immutable history, triage aliases |
| `app/assess/cvss.py` | Deterministic v3.1 parse / compute / validate (vector ↔ score ↔ severity) |
| `app/assess/profile.py` | Affected component, impact, remediation-details derivation |
| `app/assess/poc.py` | Structured, safety-bounded proof-of-concept representation |
| `app/assess/evidence.py` | Payload hashing, bounded capture, integrity verification |
| `app/assess/summary.py` | Aggregates, status/completeness classify, headline, config fingerprint & snapshot |
| `app/reporting/models.py` | `AssessmentReport`, `ReportSection` value objects |
| `app/reporting/builder.py` | Deterministic 12-section report build (markdown + JSON from one source) |
| `app/reporting/{finding_renderer,evidence_renderer,coverage_renderer,summary,redaction,export}.py` | Per-area rendering + export persistence |

## Schema & migration

`alembic/versions/a9f3e2d1c8b4_phase6_lifecycle_reporting.py` (applied):

- `Vulnerability`: `status`, `affected_component`, `parameter`, `cvss_version`,
  `cvss_vector`, `cvss_score`, `business_impact`, `technical_impact`,
  `impact_details` (JSON), `remediation_details` (JSON), `fingerprint`,
  `first_seen`, `last_seen`, `references_json`.
- `FindingStatusHistory`: append-only `from_status`/`to_status`/`actor`/`reason`/`created_at`.
- `FindingEvidence`: `request_hash`, `response_hash`, `original_size`,
  `captured_size`, `truncated`.
- `Scan`: `assessment_status`, `assessment_completeness`, `assessment_snapshot_json`.
- `ReportExport`: persisted exports with format, content hash, fingerprints, timestamps.
- `scan_config` JSON now carries Phase 6 keys: `active_testing`, `assessment_engine`,
  `auth_identities`, `ssrf_validation_url`, `ssrf_token`, `jwt_tokens`,
  `jwt_alg_none_accepted`, `installed_tools`, `tools_missing`.

## Engine integration (`app/assess/engine.py`)

`run_assessment()` now, per confirmed candidate:

1. Assigns `status="confirmed"` and calls
   `lifecycle.record_initial(..., from_status="none")` so the first history row
   documents creation.
2. Populates profile fields (component/impact/remediation) and sets
   `first_seen`/`last_seen`/`fingerprint`.
3. Writes `FindingEvidence` rows via `evidence_to_kwargs` (redacted,
   hash-verified, bounded).
4. Records the assessment snapshot (status, completeness, aggregates,
   registry + config fingerprint) on the `Scan` row.

External-adjacent tool output flows through the candidate sink
(`_ADAPTER_TOOLS = nmap, nuclei, httpx, ffuf, nikto, sqlmap, testssl`) with
dedup keys `external:{tool}:{normalize_endpoint(subject)}:{category}`; candidates
are never auto-promoted to confirmed.

## API surface

| Endpoint | Purpose |
|----------|---------|
| `GET /scans/{id}/assessment` | `summary_from_scan`: status, completeness, coverage, aggregates, headline, snapshot |
| `GET /scans/{id}/report?format=json\|markdown` | Deterministic export; persists `ReportExport`; returns `content_hash` |
| `GET /findings/{id}` | Full detail: lifecycle, CVSS block + consistency, PoC, integrity-verified evidence, history |
| `GET /findings/{id}/evidence` | Request/response proof + per-row `verify_evidence_integrity` result |
| `POST /findings/{id}/triage` | Lifecycle transition (`confirm/false_positive/duplicate/accepted_risk/resolve`), legacy `state` kept in sync |
| `POST /scans` | Accepts `active_testing` + Phase 6 config keys in `ScanCreate` |

`_vulnerability_dict` (scan detail / findings list) exposes the Phase 6 fields
inline, so the list UI renders status, component, CVSS, hashes without an extra fetch.

## Frontend

- `Scans.tsx` — assessment-status/completeness/headline banner, lifecycle
  aggregate chips, missing-tools gap banner, config booleans + config hash,
  markdown report export panel, lifecycle filter chips, and an enriched
  `FindingDetail` (CVSS consistency, component/parameter, technical/business
  impact, remediation details, PoC with steps + safety constraints,
  hash/truncation evidence, immutable history). Detail lazily fetched from
  `/findings/{id}` on expand.
- `NewScan.tsx` — explicit **active (mutating) testing** opt-in toggle; off by
  default and sent as `active_testing`.

## Tests (`tests/`)

- `test_cvss.py`, `test_finding_lifecycle.py`, `test_evidence.py`,
  `test_coverage.py`, `test_phase6_reporting.py` — new Phase 6 suites.
- Full gate (required): `pytest tests/test_tool_adapters.py
  tests/test_phase5_assessment.py tests/test_phase6_reporting.py
  tests/test_finding_lifecycle.py tests/test_evidence.py tests/test_coverage.py
  tests/test_schema.py -q` → **78 passed**.
- Frontend gate: `& node_modules/.bin/tsc --noEmit` from `frontend/`.

## Anti-fabrication guarantees carried forward

- No observation → no finding; not-installed → not executed → zero observations.
- Never "0 vulnerabilities when nothing ran": the headline is
  `0 confirmed findings; assessment coverage X%`.
- Secrets in the snapshot are booleans/labels only (`auth_identities_configured`,
  `ssrf_token_configured`, …); the registry fingerprint ties the report to the
  exact test catalogue, the config fingerprint to the exact sanitized config.