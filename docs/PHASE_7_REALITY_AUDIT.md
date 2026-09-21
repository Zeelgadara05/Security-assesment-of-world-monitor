# Phase 7 — Reality Audit

**Date:** 2026-09-20
**Scope:** Phase 7 as implemented vs `docs/PHASE_7_IMPLEMENTATION.md`. Every
claim was verified by running the real pipeline (real probes, no mocks) and
reading source at the cited lines.

## Verdict: IMPLEMENTED and honest

A real-local scan against a local HTTP fixture produced real observations,
8 evidence-backed findings, 13 stage rows, 11 executions, a `phase7` report,
and terminal state `completed_with_gaps`. The missing-tools invariant holds
end to end. Full backend suite: 252 passed. Frontend `tsc` + `build` pass.
Live API smoke: **77/77 checks green**.

## IMPLEMENTED

1. **Orchestration pipeline** — `pipeline.py::orchestrate_scan_phase7`;
   asserted 13 stages in the exact `PRECHECK..REPORTING` order (smoke check
   “report stage order”, stage rows = 13).
2. **Missing tools ⇒ gaps** — `_FAILED_STATES` includes
   `STATE_NOT_INSTALLED` (pipeline.py lines 60–62); smoke: every binary
   missing on this host recorded `not_installed`, 0 observations, and the scan
   ended `completed_with_gaps`; `coverage < 100 %`.
3. **Real probes** — `real_dns` (A record), `real_tcp` (loopback open ports),
   `real_http` (fixture on port 80) all produced real observations; rules
   fired off real data (`missing-security-header`, `outdated-jquery`,
   `server-version-banner`).
4. **Evidence attachment** — fixed `_persist_findings` to union
   `candidate.observation_ids` with matched engine-run observations; smoke
   verifies every finding cites ≥1 scan observation.
5. **Tool readiness** — `ToolReadiness` rows per planned tool via the shared
   inventory (`/tools/status`, preflight); smoke: preflight missing is a
   superset of inventory-missing tools.
6. **Typed events** — SSE `/events` + `/typed-events` emitted the full
   `['coverage','done','preflight','stage','state','tool']` set; smoke check
   asserts the complete stream.
7. **ML advisory** — `ml/advisory.py` writes `status=advisory_only`,
   `model_name=None`; `/ml-advisory` reports the gap-oriented advisory.
8. **Report** — persisted report carries `execution_platform_version=phase7`,
   13 stages, 11 executions, findings, and the platform ledger; markdown/html
   render.
9. **Frontend** — Phase 7 console + readiness preflight + report meta strip
   compile (`tsc`, zero errors) and build (vite) successfully.

## PARTIALLY_IMPLEMENTED

1. **PDF report** (`api/reports.py:64`) — downloads octet bytes of the raw
   markdown (`simulated by downloading octet raw bytes`). Functional placeholder,
   no real PDF engine. Out of Phase 7’s core honesty goals; noted for a later
   phase.
2. **AIChat** (`api/chat.py:87`) — a deterministic keyword-assisted simulator
   (marked `"simulated": true`). Not a Phase 7 feature; listed so the audit
   is exhaustive as to what is and isn’t real.

## BLOCKED_BY_ENVIRONMENT

1. **Real external binaries** — nmap, subfinder, assetfinder, dnsx, httpx,
   gau, whatweb, nuclei are not installed on this machine. The adapter layer
   is fully implemented and unit-tested; a real network scan of a live target
   cannot be demonstrated here. The pipeline handles it honestly
   (`completed_with_gaps`), which is exactly the required behaviour.
2. **ML model inference** — no model weights present; advisory mode is used
   instead (`advisory_only`, `model_name=None`).

## NOT_IMPLEMENTED

1. Nothing on the Phase 7 contract. Executions for every one of the 8 planned
   binaries and the 3 stdlib probes = **11 ToolExecution rows** on this host
   (smoke asserts this); do not expect a 13-row execution table — 13 is the
   stage count.

## Notes / follow-ups (non-blocking)

- Two JSON report shapes (persisted `reports.json_content` vs
  `builder.build()` export) — see `PHASE_7_ARCHITECTURE.md`. Documented;
  unifying them is optional.
- `datetime.utcnow()`, fastapi `on_event`, and SQLAlchemy legacy warnings are
  cosmetic; no behavioural impact seen.
- Evidence union uses `sorted(set(…))` for deterministic ordering — already
  exercised by the real-local test (findings reference pre-run observations).