# Phase 7 — Architecture

**Date:** 2026-09-20

Phase 7 is an orchestration layer on top of the existing Phase 2–6 wealth
(observations, rules, validators, report generators). This document describes
the pieces as they run today and how scan data flows end to end.

## Data model

| Model | Table | Phase-7 role |
|---|---|---|
| `Scan` | `scans` | lifecycle source of truth; `status`, `state`, `coverage`, `progress`, `preflight_json`, severity fields |
| `ScanStage` | `scan_stages` | one row per orchestration stage with `tests_executed`, `observations`, `confirmed_findings`, `duration_ms` |
| `ToolReadiness` | `tool_readiness` | per-scan, per-tool `installed/missing/disabled` declaration |
| `ToolExecution` | `tool_executions` | per attempt: `status`, `duration_ms`, `parsed_observations`, redacted command, `termination_reason` |
| `Observation` | `observations` | normalized, fingerprintable measurements (single choke point) |
| `Finding` / `FindingEvidence` | `findings`, `finding_evidence` | confirmed findings + cited observation ids |
| `FindingValidation` | `finding_validations` | validator results per finding |
| `MLInference` | `ml_inferences` | advisory rows, `status=advisory_only`, `model_name=None` |
| `Report` | `reports` | markdown + JSON report persisted per scan |

## Control flow

```
POST /scans                        (async trigger)
   └─ trigger_background_scan ── SimulationMode (env or scan_config)
        └─ orchestrate_scan_phase7(scan_id, simulation, config)
             ├─ planning:        13 stages + tool plan (7 binaries + 3 probes)
             ├─ PRECHECK .. REPORTING  [each writes a ScanStage row]
             ├─ PREFLIGHT stage:  ToolReadiness rows via shared inventory
             ├─ EXECUTION:        ExternalToolAdapter.run(cancel_check) -> BoundedRunner
             │                      real_dns / real_tcp / real_http probes
             │                      -> ToolExecution row + normalized observations
             ├─ ASSESSMENT:       run_rule_assessment(index) -> candidates
             │                      engine._persist_findings (evidence = union)
             ├─ VALIDATION:       validators -> FindingValidation rows
             ├─ FINDING_FINALIZATION/COVERAGE/REPORTING: severity, coverage %,
             │                      _build_report (markdown + json), ML advisory
             └─ _finish_terminal: terminal state (completed_with_gaps etc.)
```

## Honesty invariants

1. **Not installed ⇒ no observations.** `_FAILED_STATES` includes
   `STATE_NOT_INSTALLED` (pipeline.py lines 60–62); the adapter base returns
   `STATE_NOT_INSTALLED` with zero observations (base.py lines 242–249);
   coverage stays `< 100 %`; the scan ends `completed_with_gaps`.
2. **Reality marker.** Real scans run with `simulation=false`; report carries
   `execution_platform_version: "phase7"` and `simulation: false`. Simulation
   mode is explicit and never synthesizes observations.
3. **Evidence must cite real observations.** `_persist_findings` unions the
   candidate’s own observation ids with the matched engine-run observations,
   so every persisted finding can be traced back to concrete observations.
4. **Advisory ≠ AI.** `ml_inferences` rows carry `model_name=None` and
   `status="advisory_only"`.

## Events

`app/orchestration/events.py` emits typed events persisted per scan and
streamed via SSE: `state`, `stage`, `tool`, `preflight`, `progress`,
`coverage`, `finding`, `validation`, `done`, `error`.
`/scans/{id}/typed-events` returns them deterministically for the UI;
`/scans/{id}/events` streams live.

## Frontend wiring

- `Phase7Console.tsx` consumes `/state`, `/readiness`, `/stages`,
  `/executions`, `/typed-events`, `/ml-advisory`, `/scans/list`,
  `/compare?with_scan_id=`.
- `NewScan.tsx` consumes `/tools/status` (inventory probe) for readiness
  chips.
- `Reports.tsx` shows the persisted `reports` JSON (`/reports/{id}/json`).

## Two JSON views (intentional)

Both are produced by Phase 7 code but shaped differently:

- **`reports.json_content`** (pipeline `_build_report`): flat,
  report-consumer-oriented; used by the Reports page and PDF/markdown path.
- **`builder.build()` export** (`/scans/{id}/report?format=json`): nested
  `execution_trail { execution { stages … }, ledger { executions…, advisory… } }`;
  used by the scan report endpoint.

Changing one to match the other risks breaking the two consumers; both are
documented here so future work quotes the correct shape per endpoint.

## Runtime

- Uvicorn: `python -m uvicorn app.main:app --host 127.0.0.1 --port 8001`
- Start-up runs `verify_schema()`, so `alembic upgrade head` must run first
  against the `DATABASE_URL` (alembic/env.py reads `settings.database_url`).
- Real-local tests and the smoke harness bind `127.0.0.1:80` for the fixture
  origin (host is allowed to bind port 80).