# Phase 5 — Assessment Engine, Coverage & External Adapters

**Date:** 2026-09-20
**Repo:** `D:\CyberAgent`
**Phase:** Deterministic observation → test → validation → evidence → finding assessment,
with honest coverage accounting and normalized external-tool adapters.

## Intent

Phase 4 proved *what tools exist and whether they are installed*. Phase 5 turns the
scan into an assessment engine that can only ever report what it actually observed and
validated. The invariants are non-negotiable:

- **NO OBSERVATION → NO FINDING.** A finding exists only when at least one persisted
  observation supports it and a deterministic validator confirmed it.
- **NOT INSTALLED → NOT EXECUTED → NO FAKE RESULT.** A missing binary yields
  `Not Installed` and zero observations; it lowers coverage rather than inventing output.
- **NEVER "0 vulnerabilities" WHEN NOTHING RAN.** The engine reports
  `0 confirmed findings; assessment coverage X%`, never a clean bill of health.
- **DETERMINISTIC ONLY.** No LLM produces findings, severity, or evidence.

## Pipeline

```
Observation(s) ──▶ Applicability ──▶ Plan ──▶ Run test ──▶ Validate ──▶ Dedup ──▶ Finding
      │                (planner)              (differential)  (validator)          │
      └──────────────────────────── Evidence rows ─────────────────────────────────┘
```

| Stage | Module | Responsibility |
|-------|--------|----------------|
| Observation | `app/observations/{types,normalize,fingerprint}.py` | Canonical, redacted, fingerprinted facts |
| Catalogue | `app/assess/registry.py` | Closed set of security tests + fingerprint |
| Applicability | `app/assess/applicability.py` | `is_applicable(observation)` + capability availability |
| Plan | `app/assess/planner.py` | `plan()` / `run()` / `plan_and_run()`, per-case ledger |
| Validate | `app/assess/validators.py` | Deterministic confirmation of candidates |
| Findings | `app/assess/{models,severity,confidence,dedup}.py` | Value objects, severity, dedup |
| Evidence | `app/assess/evidence.py` | Request/response proof, redacted |
| Coverage | `app/assess/coverage.py` | `CoverageSummary`, `findings_statement` |
| DB bridge | `app/assess/engine.py` | `run_assessment()` persistence + orchestration |
| Adapters | `app/tools/adapters/` | External CLI output → normalized observations |

## Test catalogue (16 tests)

Categories and whether a test sends mutating/active traffic. All 16 are gated by
`config["active_testing"]`; passive tests run from existing observations regardless.

| Test id | Category | Mode | Confirms |
|---------|----------|------|----------|
| `http.security_headers` | headers | passive | Missing/misconfigured security headers, with a severity cap |
| `http.information_disclosure` | disclosure | passive | Version banners, stack traces, risky files |
| `auth.session_hardening` | auth | passive | Cookie flags (Secure/HttpOnly/SameSite), session exposure |
| `http.methods` | methods | active | Dangerous allowed methods (PUT/DELETE/TRACE) |
| `http.redirects` | redirects | active | Unvalidated/open redirects |
| `http.cors` | cors | active | Reflected-origin / credentialed CORS misconfig |
| `tls.configuration` | tls | passive | Weak protocols/ciphers, cert issues |
| `auth.jwt` | jwt | passive | `alg=none`, missing expiry, weak signing posture |
| `access.authorization` | authorization | active | Missing access control on protected endpoints |
| `access.idor` | idor | active | Object-reference access across identities |
| `injection.xss.reflected` | xss | active | Reflected payload unescaped in response |
| `injection.ssti` | ssti | active | Template expression evaluation |
| `injection.sqli` | sqli | active | Boolean/error differential on a parameter |
| `injection.ssrf` | ssrf | active | Out-of-band/callback validation of URL parameters |
| `graphql.introspection` | graphql | active | Introspection enabled on a GraphQL endpoint |
| `oauth.redirect` | oauth | active | Lax `redirect_uri` matching |

The registry exposes a `registry_fingerprint()`; it is stored on every coverage summary
so a report can be tied to the exact test catalogue that produced it.

## Capability matrix

A capability is *available* only when its provider actually exists. Native capabilities
are always available; external capabilities depend on the binary being on PATH.

### Native (`native_http`, `native_tls`) — always available

`http_request`, `header_analysis`, `cors_analysis`, `method_analysis`,
`redirect_analysis`, `disclosure_analysis`, `xss_validation`, `sqli_validation`,
`ssti_validation`, `authorization_testing`, `jwt_analysis`, `tls_analysis`.

### External (installable) — declared in `app/tools/capabilities.py`

| Tool | Binary | Capabilities | Active | Output |
|------|--------|--------------|:------:|--------|
| nmap | `nmap` | `port_scan`, `service_detection`, `version_detection` | yes | XML |
| nuclei | `nuclei` | `vulnerability_scan` | yes | JSONL |
| httpx | `httpx` | `http_probe`, `http_fingerprint` | yes | JSONL |
| subfinder | `subfinder` | `subdomain_enumeration` | no | text |
| assetfinder | `assetfinder` | `subdomain_enumeration` | no | text |
| dnsx | `dnsx` | `dns_resolution` | no | text |
| gau | `gau` | `url_discovery` | no | text |
| whatweb | `whatweb` | `technology_fingerprint` | yes | text |
| ffuf | `ffuf` | `directory_fuzzing`, `parameter_fuzzing` | yes | JSON |
| nikto | `nikto` | `web_server_scan` | yes | JSON |
| sqlmap | `sqlmap` | `sql_injection` | yes | text |
| testssl | `testssl` | `tls_analysis` | no | JSON |

The capability list is a static, auditable declaration. `capabilities_for()` returns an
empty `capabilities` list when the binary is absent while still exposing
`declared_capabilities`, so the UI can distinguish "cannot do this" from "not installed".

## External tool adapters (`app/tools/adapters/`)

Each adapter has one job: `target + options → run binary → parse stdout → [ToolObservation]`.

- `base.py` — `ExternalToolAdapter`, `ToolObservation`, `ToolRunResult`, `ToolParseError`,
  `safe_target()`, `redact_command()`.
- One module per tool; `registry.py` maps tool name → adapter and supports
  `adapters_for_capability(cap, installed_only=True)`.

Guarantees enforced in `base.py`:

- Missing binary → `Not Installed`, **zero** observations.
- `simulation=True` → zero observations (simulation never synthesizes evidence).
- `shell=False`; the target is stripped of control/shell characters.
- Option values following credential flags (`--header`, `--cookie`, `--token`, …) are
  masked in the persisted command via `redact_command()`.
- Malformed output → `Parse Failed` (`ToolParseError`), never a coerced finding.
- A `FORBIDDEN_OPTIONS` denylist rejects destructive flags (`dump`, `os_shell`, …).
- sqlmap is limited to boolean detection at level 1 / risk 1.
- Every `ToolObservation.to_observation_data()` routes through `build_observation`, so
  external and native observations share one redaction/normalization path.

Adapter output types: nmap → `host`/`port`/`service`; nuclei/nikto/sqlmap/testssl →
`vulnerability` (+ testssl `certificate`); httpx → `http_response`/`technology`;
ffuf → `http_endpoint`.

## Coverage semantics

`CoverageSummary` (in `coverage.py`) records:

- `tests_total`, `tests_applicable`, `tests_executed`, `tests_failed`,
  `tests_not_applicable`, `tests_skipped`
- `testcases_planned`, `testcases_executed`, `observations`
- `findings_confirmed`, `findings_by_severity`, `findings_by_confidence`
- `coverage_percent`, `not_executed[]`, `tools_missing[]`

**Coverage is execution honesty, not success:**

```
coverage_percent = tests_executed / tests_applicable × 100
```

- Not-applicable tests are excluded from the denominator and reported with a reason in
  `not_executed` (e.g. `tls.configuration` on an HTTP-only target).
- If no test is applicable, `coverage_percent` is `null` (unknown), never `100`.
- `findings_confirmed` counts **deduplicated, validated** candidates only.
- `findings_statement` renders the honest headline, e.g.
  `0 confirmed findings; assessment coverage 62.5%`.

## Orchestration & configuration

`engine.run_assessment(db, scan, simulation, config, user_id)` is called in the ANALYSIS
stage of the real workflow (`app/agents/workflow.py`), **after** Phase 3 rules, and
swallows its own errors so an assessment failure cannot fail the scan. It persists
observations, the `AssessmentTest` ledger, `Vulnerability` findings, `FindingEvidence`,
and one `native_assessment` `ToolResult`.

Recognized `config` keys (pass-through merged from the scan request):

| Key | Default | Effect |
|-----|---------|--------|
| `assessment_engine` | enabled | Set `false` to disable the engine entirely |
| `active_testing` | `false` | Opt in to mutating tests; passive tests always run |
| `auth_identities` | — | Extra identities for authorization/IDOR checks |
| `jwt_tokens` / `jwt_alg_none_accepted` | — | JWT test inputs |
| `ssrf_validation_url` / `ssrf_token` | — | SSRF callback target |
| `installed_tools` / `tools_missing` | derived | Coverage reporting of external tools |

Limits: max 25 candidate endpoints and 200 active requests per assessment; every request
is scope-guarded and only full observed URLs (`scheme://host:port/path?query`) are used
for parameter tests.

## Evidence model

- `AssessmentTest` — per-test ledger: status (`planned/not_applicable/skipped/executed/
  validated/failed/rejected`), reason, executed case count, timestamps.
- `Vulnerability` — adds `category`, `endpoint`, `http_method`, `source_test`,
  `source_tool`, `validation_reason`, `impact`, `evidence_records`.
- `FindingEvidence` — the raw, redacted request/response proof backing a finding.

All three are written through the redaction choke point in `app/observations/normalize.py`.
A finding without evidence rows is impossible by construction.

## API surface

| Endpoint | Adds |
|----------|------|
| `GET /scans/{id}` | `assessment.coverage`, `assessment.tests`, Phase 5 vuln fields, `evidence_records` |
| `GET /scans/{id}/findings` | Normalized finding shape incl. `source_test`, `evidence_records` |
| `GET /scans/{id}/coverage` | `assessment` coverage block |
| `GET /scans/{id}/observations` | Normalized observations |

Frontend `ScanDetail` (`frontend/src/pages/Scans.tsx`) renders an **Assessment coverage**
panel (coverage %, executed/applicable, not-applicable reasons, observation count, test
ledger) and a structured **evidence viewer** inside `FindingDetail`.

## What Phase 5 does *not* claim

- No exploit chaining, no post-exploitation, no destructive verification.
- No finding without a validator-confirmed observation and stored evidence.
- No coverage credit for tools that were not installed or tests that did not apply.
- Phase 6 is explicitly out of scope.

## Verification

Fast targeted suite (no external binaries required):

```
cd D:\CyberAgent\backend
venv\Scripts\python.exe -m pytest tests/test_tool_adapters.py tests/test_phase5_assessment.py tests/test_schema.py -q
```

Covers: registry fingerprint, planner gating, headers severity cap, XSS
escaped-reject/unescaped-confirm, SQLi differential confirm+reject, authorization, IDOR,
dedup, coverage honesty, a real-local-server end-to-end confirmation, the API
scan-detail shape, adapter parse/state/redaction behaviour, and the schema migration.
