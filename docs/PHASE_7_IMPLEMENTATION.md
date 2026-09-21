# Phase 7 — Implementation

**Date:** 2026-09-20
**Stage names:** The 13 orchestration stages are defined in
`app/orchestration/stages.py` (lines 9–21): `PRECHECK`,
`TARGET_NORMALIZATION`, `PASSIVE_RECON`, `DNS_DISCOVERY`,
`PORT_SERVICE_DISCOVERY`, `HTTP_DISCOVERY`, `TECHNOLOGY_IDENTIFICATION`,
`VULNERABILITY_DISCOVERY`, `DETERMINISTIC_ASSESSMENT`, `VALIDATION`,
`FINDING_FINALIZATION`, `COVERAGE`, `REPORTING`.

Phase 7 turns the existing assessment stack into a real scan execution
platform: a single async orchestration pipeline that drives tool adapters and
native probes, persists every stage and execution, streams typed lifecycle
events, and produces honest findings and a Phase-7 report. Every Phase 7
end-to-end behaviour is locked down by tests that run against the real
pipeline on this machine.

## 1. Orchestration pipeline

`app/orchestration/pipeline.py`

- `orchestrate_scan_phase7(scan_id, simulation=False, config=None)` is the
  single entry point; it loads the scan, runs planning, then each of the 13
  stages in order, moving the scan through
  `app/orchestration/state.py` states (lines 14–24: `created`, `preflight`,
  `running`, `validating`, `finalizing`, `completed`,
  `completed_with_gaps`, `blocked`, `failed`, `cancelled`).
- The state machine is enforced by `_move_state` (line 139) and
  `_finish_terminal` (lines 448–571): a terminal state is recorded with a
  human-readable `status` (`Completed` / `Partially Completed` / `Blocked` /
  `Failed` / `Cancelled`) and a persisted `completed_at` timestamp.
- **Missing tools are gaps, never success.** `_FAILED_STATES` (lines 60–62)
  includes `STATE_NOT_INSTALLED`, so a host without a planned binary yields a
  `not_installed` execution, zero fabricated observations, reduced coverage,
  and a terminal `completed_with_gaps` (never `completed`).

## 2. Planning and preflight

`app/orchestration/preflight.py`

- `plan_tasks({})` produces the stage list plus one planned tool per binary
  and one planned tool per stdlib probe (`real_dns`, `real_tcp`,
  `real_http`).
- Readiness is probed through the shared tool inventory
  (`app/tools/inventory.py`, `app/tools/scanner_tools.py`) and persisted as a
  `ToolReadiness` row per planned tool with `status ∈ {installed, missing,
  disabled}` (preflight.py lines 96–115).
- `runnable` (line 130) only requires a probe or a single installed tool; the
  pipeline never blocks on zero third-party binaries because the stdlib probes
  always run.

## 3. Execution

`app/orchestration/executions.py`

- External adapters subclass `app/tools/adapters/base.py::ExternalToolAdapter`
  and run through `BoundedRunner` (`app/execution/runner.py`) with cooperative
  cancellation and a hard timeout. The base class enforces the three honesty
  guarantees (lines 9–17): availability (missing binary → `Not Installed`,
  zero observations), execution (`shell=False`, redacted commands,
  `SENSITIVE_ARG_FLAGS`, `FORBIDDEN_OPTIONS`), and parsing (`ToolParseError` →
  `Parse Failed`, never silent coercion). Simulation mode returns
  `state=completed` with **zero** synthesized observations (lines 234–240).
- Native probes trust no network tooling: `app/tools/real_probes.py` resolves
  DNS directly, TCP-connects the `TCP_PORT_PROBE_LIST`, and performs a real
  loopback HTTP request. Their observation kinds feed the same rule engine as
  the adapters.
- Every run persists a `ToolExecution` row with `tool`, `stage`, `attempt`,
  `status`, `duration_ms`, `parsed_observations`, redacted command, and
  `termination_reason` (executions.py lines 92–111, 321–340).

## 4. Assessment and evidence

- Observations are normalized by the single choke point
  `app/observations/normalize.py::build_observation` (redaction, fingerprint,
  status) — identical for adapter output, native probes, and legacy tests.
- `run_rule_assessment` in `app/assess/engine.py` builds candidates by
  matching rules over observations against the observation index.
- `_persist_findings` attaches **evidence from the union of the candidate’s
  own observation ids and the matched engine-run observations**
  (`evidence_observation_ids = set(candidate.observation_ids) | matching`), so
  findings that correctly reference earlier probe observations never persist
  with empty evidence.
- Validators (`app/assess/validators.py`) write a `FindingValidation` row per
  check; coverage (`app/assess/coverage.py`) is computed as
  `executed / applicable` and stays < 100 % whenever binaries are missing.

## 5. ML advisory

`app/ml/advisory.py` builds a deterministic, evidence-driven advisory from the
observed findings. Rows land in `ml_inferences` with
`status="advisory_only"` and `model_name=None` (`build_advisory`, lines 85–99)
so an advisory can never be mistaken for AI output. `system.py` reports
`ml_status: "advisory_only"` when no model is configured.

## 6. Reporting

`app/reporting/`

- `generate_markdown_report_content` and `generate_html_report_content` render
  the human report from the same findings/observations used by the API.
- Two JSON views exist (both carry `execution_platform_version: "phase7"`):
  - **Persisted report** (`app/orchestration/pipeline.py::_build_report`,
    lines 453–510): top-level `target`, `findings`, `observations`,
    `preflight`, `stages` (13 rows), `executions`, `ml_advisory`, `coverage`,
    `execution_platform_version`, and `execution_trail` with
    `status/state/total_tasks/completed_tasks/failed_tasks/percent/tools`.
    Served by `app/api/reports.py` (`/reports/{id}/json`, line 48) and used by
    the Reports page.
  - **Builder export** (`app/reporting/builder.py`, lines 390–404): served by
    `/scans/{id}/report?format=json`; stages under
    `execution_trail.execution.stages`, executions under
    `execution_trail.ledger.executions`, advisory meta under
    `execution_trail.ledger.advisory`.

## 7. API surface (Phase 7)

`app/api/scans.py`: `/{scan_id}/state` (758), `/stages` (778),
`/executions` (804), `/readiness` (837), `/typed-events` (862),
`/ml-advisory` (877), `/compare?with_scan_id=` (902), `/report` (638, all
formats), `/coverage` (512), plus the SSE stream `/events` (556) emitting
typed lifecycle events (`app/orchestration/events.py`: `state`, `stage`,
`tool`, `preflight`, `progress`, `coverage`, `finding`, `validation`, `done`,
`error`). Tool probing: `/tools/inventory|status|refresh`
(`app/api/tools.py`).

## 8. Frontend

- `frontend/src/components/Phase7Console.tsx` — self-contained Phase 7 console
  for a selected scan: lifecycle state, readiness, 13 stages, executions,
  typed-event live stream, ML advisory, and cross-scan comparison.
- `frontend/src/pages/Scans.tsx` — Console/Classic toggle for the pipeline
  lifecycle panel.
- `frontend/src/pages/NewScan.tsx` — “Scanner readiness” preflight preview
  (installed vs missing tools, “will record gaps” chips).
- `frontend/src/pages/Reports.tsx` — execution meta strip on JSON reports
  (platform version, stage/execution/finding counts, advisory-only marker from
  `ml_advisory`).

Both `tsc -p tsconfig.json` and `npm run build` pass.

## 9. Tests

- `backend/tests/test_phase7_real_local_scan.py` — two tests against the real
  pipeline (no mocks): a full honest chain (probes → observations → rules →
  candidates → validators → evidence-backed findings → lifecycle → 13 stages
  → Phase-7 report → typed events), and the missing-tools invariant
  (`not_installed`, 0 observations, `failed_tasks == len(missing)`,
  coverage < 100 %).
- `test_phase7_execution.py` — unit coverage of planning, execution mapping,
  state machine, and event emission.
- Full backend suite at time of writing: **252 passed**.
- **Live smoke (real API, real postgres-sqlite):** 77/77 checks pass —
  scan ends `completed_with_gaps`, 13 stage rows, 11 executions (8 binaries
  missing + 3 stdlib probes), 8 evidence-backed findings, SSE typed-event
  stream complete, report carries phase7 metadata.