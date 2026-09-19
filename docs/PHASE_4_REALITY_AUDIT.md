# Phase 4 Reality Audit

Date: 2026-09-19
Audit scope: current "queued scan" behavior, background execution, progress reporting,
tool execution, evidence pipeline, finding lifecycle, reporting, and dashboard data.

This document is the starting point for Phase 4. It states what the system ACTUALLY
does today (verified by reading code and running the app), before Phase 4 refactors
anything. It is a *reality* audit: it calls out where behavior is fake, where it is
only partially real, and where gaps exist.

---

## 1. Who creates, queues, and executes a scan

### 1.1 Scan creation
- `POST /scans/trigger` (`backend/app/api/scans.py`) is the only way a scan is created via
  the API. It validates authentication (`get_current_user`), ensures the requested target
  is inside the user's authorized scope (declared `Project.scope_json` OR already-discovered
  `Asset` of type `domain`/`ip`), creates a `Scan` row with `status="Pending"`, and returns
  `{scan_id, target, status, simulation, created_at}`.
- The Phase 4 brief specifies `POST /scans`. Today only `/scans/trigger` exists; there is no
  `/scans` collection route and no JSON body beyond `{target}` (no config, no tool-set, no
  severity/profile control).

### 1.2 Queueing / background execution
- `trigger_background_scan(scan_id, simulation)` (`backend/app/workers/tasks.py`) runs
  synchronously inside the request handler (`/scans/trigger` calls it before returning).
  It attempts Celery (unavailable in practice), then falls back to a module-level
  `ThreadPoolExecutor(max_workers=5)` and submits `orchestrate_scan(scan_id, simulation)`.
- The request DOES return immediately (submission is non-blocking), so execution is *de
  facto* async via a thread pool — but the "queue" is an unordered `ThreadPoolExecutor`
  with no job registry, no queue position, no job identity, no persistence, and no
  cancellation. There is no way to enumerate enqueued jobs, watch a single job's lifecycle
  transitions, or cancel.

### 1.3 Scan status lifecycle
- `Scan.status` is a free string persisted in DB. The code only ever writes
  `Pending` → `Running` → `Completed` / `Failed` (`backend/app/agents/workflow.py`).
- There are NO per-stage states (QUEUED/STARTING/RECON/DISCOVERY/...), no `current_stage`,
  no progress counters, no `coverage` metric. The only progress oracle is `Scan.logs`, a
  growing text blob that the SSE endpoint tail-reads.

## 2. How a scan actually runs today (`backend/app/agents/workflow.py`)

`orchestrate_scan` is a single procedural function that:
1. Opens one `SessionLocal()`, marks the scan `Running`, writes a `[Planner Agent]` log line.
2. Runs 8 external tool adapters sequentially, each via `run_*` module functions:
   subfinder, assetfinder, dnsx, nmap, httpx, gau, whatweb, nuclei.
   Each result is persisted as a `ToolResult` row via `save_tool_result`.
   Simulation mode `time.sleep()`s and returns synthetic payloads (subdomains/ports/techs/urls),
   except nuclei whose simulation returns `vulnerabilities: []` (never fabricates findings).
3. Splits: real mode additionally runs the "real evidence pipeline" (`real_dns`, `real_tcp`,
   `real_http` probes + nuclei findings → `Observation` rows). Simulation mode skips this and
   has zero observations.
4. "Analysis": simulation forces `security_score = 100` and no findings. Real mode evaluates
   `finding_rules.evaluate_observations(observations)` → persists `Vulnerability` rows →
   recomputes `security_score` from those rows.
5. "Reporting": builds a `Report` row (markdown/html/json) strictly from persisted findings +
   observations, marks the scan `Completed` with `completed_at`, closes the session.

### 2.1 What is REAL today
- Tool not-installed detection: `is_tool_installed` via `shutil.which`; adapters return an
  explicit `Not Installed` state and never fake output for a missing binary.
- Invocation safety: every external CLI runs with `shell=False` and a list of args
  (`subprocess.run(args, ...)`), inputs pass through `sanitize_input`.
- Hard timeout: `BINARY_TIMEOUT_SECONDS = 90`, mapped to a `Timeout` tool state.
- Evidence pipeline in real mode: genuine stdlib probes (`socket.getaddrinfo`, TCP connect,
  `urllib` HTTP GET) yield `Observation` rows; findings come only from `finding_rules`
  evaluating those observations. No decision engine reads fake data.
- Findings triage: real POST `/findings/{id}/triage` state machine, ownership-enforced.
- Reports: strictly downstream of persisted rows.

### 2.2 What is FAKE / mislabeled today
- `Scan.logs` are heavily theatrical ("[Planner Agent] ...", "[AI Analysis Agent] ...",
  "[Reporting Agent] Completed. Report artifacts ready for download.") and include
  1.5–2s `time.sleep()` calls that simulate "agent deliberation". No such agents exist.
- The SSE "logs" stream is a poll of the `logs` blob; there are no typed events
  (stage started/completed, tool started/completed, finding produced).
- Summary score: in simulation mode the workflow writes `security_score = 100` — a hardcoded
  "clean baseline", not a real metric.
- There is NO `coverage` metric anywhere (no "which planned tasks actually executed").
- Simulation is the default (`SIMULATION_MODE` default `true`). A fresh install therefore
  produces scans whose subdomains/ports/techs/URLs are fabricated strings, even though the
  finding engine (correctly) stays silent. The dashboard therefore shows synthetic ports/
  assets in simulation mode.
- The chat endpoint is deterministic keyword matching, yet titles itself "AI Security
  Copilot" and does `{"simulated": true}` — the "AI assistant" billing is aspirational.
- There is no `GET /tools/inventory`; tool availability is invisible to the UI.
- There is no cancellation endpoint; a running scan cannot be stopped.

## 3. Data flow today (verified)

```
POST /scans/trigger
  -> scope check (Project.scope_json / discovered Assets)
  -> Scan(status=Pending) created
  -> ThreadPoolExecutor.submit(orchestrate_scan)   [fire-and-forget]
        -> status Running
        -> ToolResult rows for subfinder, assetfinder, dnsx, nmap, httpx, gau, whatweb, nuclei
        -> (real) Observation rows via real_dns/real_tcp/real_http/nuclei
        -> Vulnerability rows via finding_rules over observations
        -> security_score from findings
        -> Report rows
        -> status Completed/Failed

GET /scans/list        -> status, score per scan
GET /scans/{id}/details-> status, score, logs blob, vulnerabilities[], tools[{name,status}]
GET /scans/summary     -> aggregated real numbers (severity, ports, status counts, score history)
GET /scans/{id}/stream -> SSE tailing Scan.logs until terminal state
GET /auth/assets       -> discovered assets
GET /reports/...       -> report artifacts for a completed scan
POST /findings/{id}/triage -> triage state machine
```

## 4. Gaps that Phase 4 must close (mapped to brief steps)

| # | Gap | Step(s) |
|---|-----|---------|
| 1 | No job lifecycle / stage states, no per-stage progress, no coverage | 2, 3, 5, 22, 23 |
| 2 | No real background worker with job registry & cancellation | 4, 6 |
| 3 | No `POST /scans`, no scan config (tools/severity/profile) | 7, 46 |
| 4 | No `GET /scans/{id}` detail w/ pipeline, no `/events` SSE, no `/observations`, `/findings`, `/coverage` | 43, 44, 45 |
| 5 | No cancellation; thread-pool jobs unreachable | 6 |
| 6 | No tool inventory / adapter contract / version detection | 8, 9, 12, 47 |
| 7 | Progress is a log blob, not structured metadata | 3, 5 |
| 8 | NO real subprocess cancellation; adapters block on `subprocess.run` | 4, 6 |
| 9 | Findings engine already real; needs validation/correlation/severity/cwe/coverage hardening | 26–32 |
| 10 | Score is clean-but-100 in sim; must be risk-from-findings, separated from coverage | 33 |
| 11 | Reports exist (JSON/Markdown/HTML/PDF-mock) but lack coverage/vulnerabilities count/metadata | 34–39 |
| 12 | Simulation default produces fabricated recon assets on dashboards | 42 |
| 13 | UI: no tool health, no live scan detail timeline, fake rename for "AI Copilot", fake settings toggles | 20, 29, 30, 36, 37, 41 |
| 14 | No tool matrix doc / install verification | 60 |
| 15 | Tests cover lifecycle/simulation; none cover coverage, SSE events, cancellation, out-of-scope filtering, two-user isolation on assets/findings flows | 24, 25, 61 |

## 5. Honest inventory — what each external tool does today

| Tool | Adapter | Installed on this env? | Real invocation |
|------|---------|------------------------|------------------|
| subfinder | subfinder -d <target> -silent | not verified (Phase 4 verifies) | passive subdomain lists |
| assetfinder | assetfinder --subs-only <target> | not verified | passive subdomains |
| dnsx | dnsx -d <sub> -resp-only -silent (per subdomain) | not verified | DNS resolution |
| nmap | nmap -sV -T4 -F <target> | not verified | port/service scan |
| httpx | httpx -u <target> -status-code -title -web-server -silent | not verified | HTTP probing |
| gau | gau <target> | not verified | URL discovery |
| whatweb | whatweb <target> | not verified | tech fingerprint |
| nuclei | nuclei -target <target> -json -silent | not verified | vulnerability engine |

Simulation flag controls whether `run_*` returns synthetic vs real data. In real mode all 8
go through `subprocess.run(shell=False, timeout=90)`.

## 6. Conclusion

The system is honest where it matters most (findings only ever derive from persisted
observations; tool availability never faked; scope enforced; ownership enforced) but is
NOT yet a production scan engine: there is no job lifecycle, no worker/queue with control,
no progress/coverage, no cancellation, no tool inventory, and the UI pairs real dashboard
numbers with theatrical agent logs. Phase 4 replaces the orchestration layer with a real
job model + worker + staged pipeline + structured progress + cancellation + inventory,
keeps the evidence-first finding engine, and fixes the UI naming/simulations.