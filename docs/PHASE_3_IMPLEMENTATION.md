# Phase 3 — Evidence-Based Findings Pipeline

**Date:** 2026-09-19
**Repo:** `D:\CyberAgent`
**Baseline:** `docs/PHASE_2_IMPLEMENTATION.md` (completed 2026-09-19)

## Goal

Replace the simulated/hardcoded finding path with a genuine, traceable pipeline:
**recon → persisted observations → evidence → rule engine → triage/dedup → score →
persisted findings → report/dashboard**, with the hard rule that **no observation or
evidence ⇒ no finding**. Empty scans must produce 0 findings and a score of 100, and
every finding must be traceable to concrete persisted evidence.

## Scope guarding

Not implemented (deferred): external scanners remain **NOT INSTALLED** on this machine
(no fabrication); real PDF generation; scope re-validation of discovered subdomains
(see audit doc — probe list is `[target]` only in practice); LLM/RAG/ML; Docker/CI;
Postgres migration. This is the final delivery phase — the repository is left stopped.

## Design decisions

- **Observations are the single source of truth.** A new persisted `observations`
  table stores every probe result verbatim (`tool_name`, `kind`, `subject`,
  `data_json`, `raw_output`). Findings reference the observations that produced them.
- **Rule engine in `app/assess/finding_rules.py`.** `evaluate_observations` maps
  persisted observations to candidates with a `rule_id`, `dedup_key`, `confidence`,
  severity, CWE, and proof. Rules: `missing-security-header` (Low/CWE-693),
  `server-version-banner` (Info/CWE-200, requires a real banner/version),
  `outdated-jquery` (Medium/CVE-2015-9251, only < 3.7.0), `nuclei-reported-finding`
  (re-uses real nuclei engine output when installed).
- **Dedup + score.** Candidates are deduplicated against persisted open `dedup_key`s.
  Score starts at 100 and deducts Critical 25 / High 15 / Medium 8 / Low 3 / Info 0
  (floor 10). `FALSE_POSITIVE / DUPLICATE / RESOLVED` states are excluded.
- **Triage without auto-confirm.** `POST /findings/{id}/triage` supports
  `confirm | false_positive | duplicate | accepted_risk | resolve`, ownership-checked;
  an action must always be chosen explicitly.
- **Reports are strictly downstream.** Markdown/HTML/JSON are generated only from the
  persisted findings and observations after the analysis stage commits.
- **Simulation baseline.** In `SIMULATION_MODE=true`, no probes run and the real rule
  engine produces nothing from an empty observation set → 0 findings, score 100, with
  `[SIMULATION]` markers in tool rows and logs.
- **Dashboard reads `/scans/summary`.** All cards/charts derive from persisted
  user-owned rows; empty states are shown instead of fabricated demo data.

## What changed

### Backend
- `database/models.py` — new `Observation` model; `Vulnerability` gained `cwe`,
  `rule_id`, `dedup_key`, `confidence`, `state` (default `NEW`), `evidence`,
  `evidence_observation_ids`, `updated_at`, `resolved_at`; `Scan.observations`
  relationship.
- `alembic/versions/8f3a2c51d94e6b77_observations_and_finding_pipeline.py` — creates
  `observations`, adds the vulnerability columns (down_revision `e8244e2719f7`).
- `app/tools/real_probes.py` (new) — stdlib `dns_probe`, `tcp_probe`, `http_probe`,
  `extract_jquery_version`, `body_match_observation`. Real network I/O; errors are
  observations, never silence.
- `app/assess/finding_rules.py` + `__init__.py` (new) — rule engine, dedup, scoring.
- `app/tools/scanner_tools.py` — `NucleiAdapter.simulate()` no longer fabricates
  findings; `run_real` normalizes nuclei records with `matched_at/template_id`.
- `app/agents/workflow.py` (rewritten analysis stage) — real mode runs the evidence
  pipeline, analysis rule engine, dedup, scoring; report generated from persisted data.
- `app/api/findings.py` (new) — triage endpoint.
- `app/api/scans.py` — details include the new finding fields; new `/scans/summary`.
- `app/api/chat.py` (rewritten) — assistant answers only from persisted findings.
- `app/main.py` — registers the findings router.

### Frontend
- `src/pages/Dashboard.tsx` — consumes `/scans/summary` for the score card, open
  findings card (renamed from "Known Vulnerabilities"), score history area chart,
  severity pie, and open-ports bar chart; no hardcoded figures, empty states added.

### Tests
- `tests/test_findings_pipeline.py` (new, 17 tests) — rule engine, real probes,
  triage/ownership, summary, and a network-free real-mode workflow end-to-end
  (observations persisted, findings with evidence, score deductions, report payload
  from persisted rows) plus a simulation-workflow zero-findings/score-100 check.
- `tests/test_schema.py` — `observations` table + `HEAD_REVISION=8f3a2c51d94e6b77`.

## Verification

- Backend suite: `cd backend; venv\Scripts\python.exe -m pytest -q` → **98 passed**.
- Migration parity: `venv\Scripts\python.exe -m alembic upgrade head` + `alembic check`
  → "No new upgrade operations detected".
- Frontend: `cd frontend; npm run build` → tsc + vite succeed (chunk-size warning
  only, pre-existing).

## Run it

1. Backend on `127.0.0.1:8003` (simulation still on by default via env): real
   evidence pipeline activates when `SIMULATION_MODE=false`.
2. Authorize a target in scope, trigger a scan → real DNS/TCP/HTTP probes persist
   observations; findings appear only where evidence exists.
3. Inspect `/scans/summary` (dashboard) and `/reports` for the persisted trail.