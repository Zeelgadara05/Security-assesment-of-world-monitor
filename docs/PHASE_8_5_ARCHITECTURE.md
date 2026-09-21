# Phase 8.5 — Architecture

How the product represents its purpose: two clearly differentiated assessment
paths sharing one execution engine, with SIH26163 coverage derived from real
execution and every claim traceable to persisted state.

## 1. Two paths, one engine

```
                 ┌───────────────────────────┐
  World Monitor  │  /scans (assessment_type=  │  Custom authorized
  deployment ───▶│  world_monitor)            │◀─── target
  (registered)   │           │                │     (in-scope host)
                 └───────────┼────────────────┘
                             ▼
            Phase 7 execution platform (13 stages)
   preflight → discovery → assess → validate → report
                             │
        Observation → Candidate → Validation → Finding
                             │
                   Coverage (SIH26163) + Report
```

- `Scan.assessment_type` records which path produced the run. The engine is
  identical; only the target resolution and the authorization framing differ.
- World Monitor runs resolve a registered `WorldMonitorTarget` the caller owns;
  custom runs use the supplied in-scope target. Both pass the server-side scope
  guard — the real control. The UI acknowledgement is an audit record
  (`authorization_acknowledged`, `authorization_acknowledged_at`), not the
  enforcement boundary.

## 2. Epistemic model (nothing is fabricated)

| Layer | Meaning | Source |
|---|---|---|
| Observation | Raw fact from a real probe/tool | `app/assess`, persisted `Observation` |
| Candidate | Finding proposed by a rule/tool, not yet validated | `Vulnerability.status = candidate` |
| Validated finding | Candidate confirmed by a deterministic validator | `FindingValidation.status = confirmed` |
| Evidence | Request/response comparison backing a finding | `FindingEvidence`, integrity hashes |
| ML Advisory | Inferred coverage-gap guidance; **never** a finding | `app/ml/advisory.py` |

Report provenance exposes this: `validated` vs `observed`. The ML advisory is
labelled *inferred — not a finding* and never creates or changes a finding.

## 3. SIH26163 coverage

`app/assess/sih.py` is the single mapping from rule-level categories to the seven
SIH areas. Coverage is computed from the persisted `AssessmentTest` ledger:

- `applicable = total - not_applicable`
- `coverage_percent = executed / applicable` (or `null` when `applicable == 0`)
- status: `covered` (all applicable executed) | `partial` | `not_assessed`

A category may belong to more than one area; the same executed test then
contributes to each area it genuinely exercises. Coverage describes the
assessment performed — it is never a security score. Missing tools reduce
applicable execution and surface as `completed_with_gaps`, not success.

## 4. API surface (Phase 8.5 additions)

| Endpoint | Purpose |
|---|---|
| `POST /scans` | accepts `assessment_type` + `authorization_acknowledged` |
| `GET /scans/{id}` | now includes `assessment.sih` |
| `GET /findings` | cross-assessment list with `sih_area` / `category` / `severity` / `status` filters |
| `GET /scans/{id}/report` | SIH coverage section + provenance + ML advisory label |

## 5. Frontend architecture

- Routes: `/` Overview, `/scans` Assessments, `/findings` Findings, `/reports`
  Reports, `/assets`, `/tools`, `/chat`, `/knowledge`, `/settings`.
- `NewScan.tsx` is a three-step wizard; `Scans.tsx` renders the assessment detail
  (lifecycle, SIH coverage, typed SSE console, tools, findings); `Findings.tsx`
  is the cross-assessment view; `Reports.tsx` previews/export the backend report.
- The frontend consumes typed events and persisted state only; it never
  synthesizes findings, endpoints or coverage.

## 6. Invariants preserved

1. Persisted-tool SSE replay contract (`/scans/{id}` preloads tools and the event
   stream replays every persisted `ToolResult`; the UI dedupes by name).
2. No confirmed finding without verifiable evidence.
3. Server-side scope guard is the real authorization control.
4. `execution_platform_version="phase7"`; 13-section report structure stable.
5. Deterministic reports: two builds of identical state are byte-identical.
