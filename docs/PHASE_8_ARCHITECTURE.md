# Phase 8 — Architecture

**Date:** 2026-09-21
**Scope:** internal design of the World Monitor Integration Foundation. Read with
`PHASE_8_IMPLEMENTATION.md` (what shipped) and `PHASE_8_REALITY_AUDIT.md` (what
was verified).

## 1. Design principle: one observation pipeline

Phase 7 already had a single normalized observation store fed by the real probe
layer (`app/tools/real_probes.py`) via `app/observations/normalize.py`. Phase 8
does **not** add a second pipeline. The World Monitor integration is a new
*source* whose facts are pushed through the same `build_observation()` function
and the same `Observation` ORM row. Consequences:

- Redaction is centralized: any sensitive header/value is scrubbed once, at the
  choke point, regardless of source.
- The assessment engine, coverage accounting, findings/evidence, and reporting
  stay source-agnostic — they see observations, not integrations.

```
             ┌───────────────────────────────────────────┐
             │            Orchestration (Phase 7)         │
             │  stages.enabled() · preflight · executions │
             └───────┬───────────────────────────────────┘
                     │ world_monitor_discovery (conditional)
                     ▼
        ┌────────────────────────────────────────┐
        │   app/integrations/world_monitor/       │
        │   provider.py  ── health.py             │
        │        │         discovery.py           │
        │        ▼                                │
        │   normalizers.py                        │
        └───────┬─────────────────────────────────┘
                │ build_observation(**kwargs)
                ▼
   ┌──────────────────────────────────────────────┐
   │ app/observations/normalize.py (redact)        │
   │            ▼ Observation rows                 │
   │   assess engine → findings → report           │
   └──────────────────────────────────────────────┘
```

## 2. Component boundaries

### 2.1 `WorldMonitorProvider` — the only network boundary
Everything outside the package talks to the provider, never to `SafeHttpClient`
directly. The provider:
1. loads the deployment (DB target for the owning project, or explicit config),
2. runs `check_health` / `discover` through the shared, scope-guarded
   `SafeHttpClient`,
3. converts results into typed `DiscoveryResult` / `HealthResult`,
4. updates the deployment row (`status`, `health_json`, `discovery_json`,
   `discovered_version`, `error`),
5. replaces the observed API inventory (`world_monitor_api_endpoints`).

### 2.2 `health.py` / `discovery.py`
Both are **config-driven, not crawler-driven**. `discovery.py` probes only the
URLs the deployment explicitly declares (base, API base, OpenAPI). If OpenAPI
is absent, endpoints are `[]` — never inferred from a guessed route list.
`metadata` / `frontend` / `rpc` surfaces are recorded as `unsupported` steps,
not probed speculatively.

### 2.3 `normalizers.py`
Turns typed results into `build_observation` kwargs with:
`project_id`, `scan_id`, `source="world_monitor"`, `source_type`,
`target_id`, `observation_time`, and a type from the shared vocabulary
(`http_response`, `certificate`, `api_route`, `error`) with an honest `status`
(`observed`, `unreachable`). No field is invented; absent data is omitted.

## 3. Scope and safety

| Concern | Mechanism |
| --- | --- |
| Authorization | `SafeHttpClient` enforces the scan/global scope; a redirect or URL leaving scope raises `OutOfScopeError`. |
| Blocked ≠ failed | A scope violation is recorded as `blocked` (never retried, never downgraded to `unavailable`). |
| SSRF / cross-host | API base and OpenAPI URLs must share the deployment host; otherwise registration is rejected `422`. |
| Secret leakage | `set-cookie` and other sensitive headers remain `<REDACTED>`; cookie capture stores **names + flags only**, values discarded at capture. |
| Data isolation | Targets are reached only through the owning user→project chain; non-owner lookups return `404`. |
| Schema integrity | Additive migration only; `verify_schema()` fails loudly at startup if the DB is not at head. |

## 4. Pipeline integration

- **Planning:** `stages.enabled("world_monitor_discovery", config)` is true only
  when the scan config references a deployment, so ordinary scans carry no
  misleading World Monitor stage.
- **Preflight:** the probe is a stdlib/native capability (always installed);
  when a scan does not reference a deployment it is omitted from the readiness
  snapshot entirely.
- **Execution:** `execute_tool` routes the tool to
  `_run_world_monitor_discovery`, including when the scan explicitly disabled it,
  so the execution row records the precise honest reason (`not_configured` vs
  `disabled by scan configuration`) instead of a generic skip.
- **Assessment:** the native engine reads WM observations like any others;
  e.g. HTTP responses contribute to header/TLS/disclosure checks and the new
  `cookies.security_attributes` test.

## 5. Data model

```
world_monitor_targets
  id, project_id, base_url, api_base_url?, openapi_url?,
  status, health_json, discovery_json, discovered_version, error,
  created_at, updated_at
        │ 1
        │
        │ N
world_monitor_api_endpoints
  id, target_id, method, path, operation_id?, tags_json?, source,
  authentication_hint?, observation_id?, created_at
```

Connectivity `status` vocabulary:
`not_configured | checking | reachable | unavailable | partially_discovered |
discovered`. There is deliberately **no** `secure`/`insecure` at this layer.

## 6. Frontend surface

- `NewScan.tsx` sends `world_monitor: {target_id}` (or an explicit URL config)
  as part of the scan payload; it is optional and absent by default.
- `Phase7Console.tsx` mirrors WM state from `/world-monitor/targets` and the
  scan's executions, and drives `check` / `discover` / `inventory` through the
  live API. The UI displays honest states; it computes no verdicts.

## 7. Compatibility

`execution_platform_version` stays `"phase7"`. Phase 7 report fields, SSE
(`/events`, `/typed-events`), coverage, and preflight endpoints are unchanged.
Phase 8 is strictly additive at the API, DB, and pipeline levels.
