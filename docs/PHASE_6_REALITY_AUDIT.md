# Phase 6 — Reality Audit (Phase 5)

**Date:** 2026-09-20
**Repo:** `D:\CyberAgent`
**Scope:** Actual repository vs `docs/PHASE_5_IMPLEMENTATION.md`. Every claim
below was verified by reading source at the cited line numbers. No files were
modified during this audit.

## Verdict

Phase 5 as documented is **substantially implemented and honest**. The core
invariants are enforced in code, enforced by migration, and covered by 152
tests including real-workflow and real-HTTP end-to-end tests. There are no
Phase 5 defects that would compromise Phase 6 correctness if fixed first; the
follow-up items are additive.

## 1. Observations pipeline — IMPLEMENTED

`app/observations/{types,normalize,fingerprint}.py`

- `types.py`: `OBS_VULNERABILITY = "vulnerability"` (line 31) in the closed
  `OBSERVATION_TYPES` tuple (line 38); `STATUS_*` (42-46); `SOURCE_*` (52-57).
- `normalize.py`: `REDACTED` (25), `SENSITIVE_HEADERS` (28-37), `SENSITIVE_KEYS`
  (40-64), bearer/JWT/query-secret regexes (66-70), `redact_text` (73),
  `redact_headers` (83), `redact_mapping` (100), `normalize_endpoint` (114),
  `build_observation` (146) — a single redaction/normalization choke point.
- `fingerprint.py`: deterministic SHA-256 fingerprints; `finding_fingerprint`
  consumed by `dedup.py`.

## 2. Assess core — IMPLEMENTED (strong)

`app/assess/{models,severity,confidence,dedup,evidence,validators,registry,applicability,planner,coverage,engine,finding_rules}.py`

- `severity.py`: `compute_severity(SeverityInput)` (line 55) computed from
  category + impact factors, not hardcoded; `_CATEGORY_BASE` (20-39).
- `coverage.py`: `CoverageSummary` (23), `findings_statement` (63-71) with the
  exact honest wording and `coverage_percent = executed / applicable` (103),
  `None` when nothing applicable (102-105); `registry_fingerprint` carried (77).
- `engine.py`: `run_assessment(db, scan, simulation=True, config=None, user_id=None)`
  (142); `_MAX_ENDPOINTS=25`, `_MAX_REQUESTS=200` (24-25); scope guard via
  `app.core.auth.is_target_in_scope` (35-51); persists observations,
  `assessment_tests` ledger, `Vulnerability`, `FindingEvidence`, one
  `native_assessment` `ToolResult` (167-174, 342-352).
- `planner.py`: plan/run/plan_and_run keep not-applicable tests in the report.
- `evidence.py`: evidence kwargs carry `redaction_status="redacted"`.
- Note: engine sets `rule_id=candidate.category` (engine.py:244); dedup then
  uses `finding_fingerprint(category, endpoint, ...)`.

## 3. Test catalogue — IMPLEMENTED

`app/assess/tests/`: 19 files (16 tests + base/util/`__init__`); all 16 ids
match the doc table. `base.py` gates active tests on `context.active_testing`
(53); candidates only via validated `result.confirmed` (104); `build_candidate`
supports explicit severity (114-140). `tls`/`jwt` override `is_applicable`.

## 4. HTTP layer — IMPLEMENTED

`app/http/{client,requests,responses,fingerprints}.py` — `OutOfScopeError`,
`RequestLimitExceeded`, `HttpLimits` (max 200/scan, 40/test, 8s timeout, 200 KB
body cap, 4 concurrency), `SafeHttpClient` scope-guarded per hop, `HTTPResponse`
with differential helpers, `fetch_tls_info` for TLS.

## 5. Tools & adapters — IMPLEMENTED, one doc inaccuracy

`scanner_tools.py` (honest states + Windows PATH merge + `shell=False`),
`capabilities.py` (12 native + 12 external), `inventory.py` (which + version),
`real_probes.py`. `app/tools/adapters/` = 7 real adapters (nmap, nuclei, httpx,
ffuf, nikto, sqlmap, testssl) with `ToolObservation`/`ToolRunResult`,
`redact_command`, `safe_target`, forbidden-option denylist, and
"not-installed / simulation / malformed output ⇒ zero or typed observations".

- **Doc discrepancy:** the doc's "one module per tool" claim covers only 7 of
  the 12 external tools; subfinder/assetfinder/dnsx/gau/whatweb live only in
  `scanner_tools.py`. Not a functional defect.

## 6. Workflow — IMPLEMENTED

- `run_assessment` called at `workflow.py:295` in ANALYSIS, real mode only,
  wrapped in try/except (292-315); `security_score` recomputed after Phase 3
  (281) and after Phase 5 (308).
- `_merge_config` (42-69) matches the doc's config table exactly.
- SSE (`GET /scans/{id}/events`, scans.py:488) streams lifecycle; assessment
  coverage is not streamed (doc does not claim it).

## 7. Database models — IMPLEMENTED (Phase 6 additive gaps)

- `Vulnerability` (130-173) has Phase 3 + Phase 5 fields. **Missing for Phase 6:**
  `description`, `affected_component`, `parameter`, `cvss_version`,
  `cvss_vector`, `cvss_score`, `business_impact`, `technical_impact`,
  `references`, `first_seen`, `last_seen`, `fingerprint`, `confidence`,
  `status`; no `finding_status_history` table.
- `FindingEvidence` (283-306): **missing** `request_hash`, `response_hash`,
  size/truncation columns.
- `AssessmentTest` (248-280): full ledger incl. statuses + reason. Good.
- `Scan`: no `assessment_status` / `assessment_completeness` / config snapshot.

## 8. Migrations — IMPLEMENTED

Chain `d1c4eef2b66c → e8244e2719f7 → 8f3a2c51d94e6b77 → 5c1d34a9e72f →
8b1f4d2a6c30` (Phase 5). `tests/test_schema.py` updates match HEAD and tables.

## 9. API — IMPLEMENTED; gaps

- `GET /scans/{id}` (384) returns `assessment.coverage` + `assessment.tests`;
  `_vulnerability_dict` (351-381) + `_finding_evidence` (330-348). Ownership
  enforced via `get_owned_scan` (auth.py:114) on detail/findings/observations/
  events/cancel.
- **Gap A:** `ScanCreate` (24) accepts only target/tools/severity/profile, so
  `active_testing`, `auth_identities`, `ssrf_validation_url`, `jwt_tokens` are
  unreachable from the public API; active testing is effectively always off via
  `POST /scans`.
- **Gap B:** `GET` serialization of evidence (`_finding_evidence`) omits the
  redacted `request_json`/`response_json` proof.

## 10. Frontend — IMPLEMENTED (minor gaps)

`Scans.tsx` renders the assessment coverage panel (353-397) and structured
evidence viewer (500-595). **Missing:** finding filters/sorting, finding status
badges, CVSS/impact/remediation/history sections, PoC viewer, per-test
validation_result, no-`active_testing` toggle in `NewScan.tsx`.

## 11. Tests — IMPLEMENTED

16 modules / 152 tests. Invariants covered: no observation → no finding;
missing headers only from real observation; simulation → 0 findings; real
workflow e2e → observations+findings+report; schema/head; adapters; scope.

## 12. Defects that must be fixed before Phase 6

1. **Config-surface gap** — assessment config not accepted by `POST /scans`
   (compromises Phase 6 configuration snapshot and active-testing UI).
2. **Evidence API drops proof** — evidence viewer cannot show request/response
   (compromises Phase 6 evidence viewer + reproducibility).
3. **Adapter doc overstatement** — annotate/correct `PHASE_5_IMPLEMENTATION.md`.
4. External vuln observations (`OBS_VULNERABILITY`/`OBS_DISCLOSURE`) are
   persisted but never surface as *candidate* findings — Phase 6 must add the
   candidate sink so external tool output cannot silently become confirmed.

## Recommended Phase 6 order

Finding lifecycle/model → CVSS → evidence integrity → impact/remediation/PoC →
assessment summary/completeness/snapshot → reporting/export → API → frontend →
tests → docs.