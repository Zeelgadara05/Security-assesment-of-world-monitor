# Assessment Reporting: Status, Completeness, Snapshot & Export

**Module:** `app/assess/summary.py`, `app/reporting/*`

## Assessment status (never a security verdict)

`classify()` reduces the persisted ledger into a status + completeness pair.
The output describes *what assessment was performed*, not the target's posture.

| Status | Meaning |
|--------|---------|
| `not_started` | No coverage recorded (simulation/disabled paths snapshot this) |
| `running` | Reserved; not yet set by the engine |
| `completed` | Full applicable coverage, no material gaps, >0 applicable, >0 executed |
| `completed_with_gaps` | Anything less: missing tools, failed/skipped tests, unknown or partial coverage |
| `failed` | Reserved for hard execution failure |

### Completeness

| Completeness | Rule |
|--------------|------|
| `complete` | Coverage 100%, no gaps, applicable>0 and executed>0 |
| `partial` | Applicable>0, coverage ≥ 50% but gaps exist |
| `minimal` | Applicable>0, coverage < 50% |
| `unknown` | No coverage percent available |

`material_gaps = tests_failed>0 OR tests_skipped>0 OR tools_missing OR coverage_percent is None OR coverage_percent < 100.0`.

## Headline

`headline()` is deterministic and built only from stored state:

- No coverage → `"No applicable tests; assessment coverage unknown."`
- Otherwise → `"{N} confirmed finding(s); assessment coverage {P:.1f}%."`
  (with `assessment incomplete.` appended for `completed_with_gaps`/`failed`).
- Never "0 vulnerabilities": zero is phrased `0 confirmed findings`.

## Snapshot & fingerprints

`snapshot()` persists on the `Scan` row (`assessment_snapshot_json`):

```jsonc
{
  "assessment_version": "phase6",
  "registry_fingerprint": "<sha256 of test catalogue>",
  "config_fingerprint": "<sha256 of sanitized config>",
  "configuration": {
    "active_testing": true,
    "auth_identities_configured": true,
    "auth_identities_labels": ["admin", "member"],
    "jwt_tokens_configured": false,
    "ssrf_validation_configured": false,
    "tools_missing": ["sqlmap"],
    "limits": { "max_candidate_endpoints": 25, "max_active_requests": 200, "request_timeout_seconds": 8.0 }
  },
  "scope": { "target": "...", "declared_scope": [...], "assets": [...] },
  "generated_at": "...",
  "aggregate": { "total_findings": 3, "total_confirmed": 1, "by_status": {...} }
}
```

- Secrets never persist: `auth_identities` → booleans + labels; `jwt_tokens` /
  `ssrf_token` → `*_configured` booleans.
- `config_fingerprint` = SHA-256 over `sanitized_config(config)` canonical JSON.
- `registry_fingerprint` from `app/assess/registry.default_registry().fingerprint()`.

## Report builder (`app/reporting/builder.py`)

`build(db, scan)` produces markdown + JSON from a single `sections` list, plus
`AssessmentReport` metadata. The section roster is fixed so exports are stable:

| # | Section id | Title |
|---|------------|-------|
| 1 | `executive_summary` | Executive Summary |
| 2 | `assessment_completeness` | Assessment Completeness & Configuration |
| 3 | `scope` | Scope & Authorized Targets |
| 4 | `methodology` | Methodology |
| 5 | `coverage` | Coverage & Test Ledger |
| 6 | `findings` | Confirmed Findings |
| 7 | `candidates` | Candidate Findings (external, not confirmed) |
| 8 | `evidence` | Evidence Trace |
| 9 | `remediation` | Remediation Guidance |
| 10 | `tools` | Tool Availability |
| 11 | `limitations` | Limitations |
| 12 | `reproducibility` | Reproducibility |

Markdown uses `## {title}` headings for sections 2–12; the executive summary is
the bare `# Assessment report — {target}` header block. A closing **Notice**
states that absence of a finding means the area was not asserted vulnerable
under executed tests — not that the area is clean.

Rules enforced:
- Cover inner text is rendered by `coverage_renderer.coverage_markdown`.
- Findings are rendered by `finding_renderer.render_finding` /
  `finding_to_markdown` (includes CVSS block + history + PoC).
- Evidence rendered by `evidence_renderer.render_evidence` with per-row
  integrity verdict.
- `Limitations` comes from `summary.limitations(snapshot, coverage, has_findings)`.

## Export (`app/reporting/export.py`)

- `render_json` / `render_markdown` produce the deterministic payloads.
- `content_hash(payload)` = SHA-256 of the rendered payload.
- `persist_export(db, ...)` writes a `ReportExport` row (format, payload, content
  JSON or markdown, fingerprints, user id).
- API: `GET /scans/{id}/report?format=json|markdown` returns
  `{format, scan_id, target, generated_at, registry_fingerprint,
  config_fingerprint, content_hash, report}`.

## Verification

- `tests/test_phase6_reporting.py` covers round-trip build values, headline
  phrasing, JSON determinism, `content_hash` stability, and the
  zero-findings-with-gaps path.
- `tests/test_coverage.py` covers `classify` across partial/minimal/unknown,
  coverage percent edge cases, and the `completed` vs `completed_with_gaps` split.