# Phase 8 — Implementation

**Date:** 2026-09-21
**Module:** World Monitor Integration Foundation & Real Assessment Pipeline
**Status:** implemented; full backend suite **301 passed**, frontend `tsc` + `vite build` green.

## 1. Goal

Integrate an authorized **World Monitor** deployment as a first-class target of
the existing assessment platform: probe it over real sockets, normalize every
observed fact into the single existing observation pipeline, and let the
Phase 5 native assessment engine derive evidence-backed findings from it — with
no fabricated data, no guessed endpoints, and no second observation format.

## 2. What was built

### 2.1 Configuration (`app/config.py`, `.env.example`)
`WORLD_MONITOR_BASE_URL`, `WORLD_MONITOR_API_BASE_URL`,
`WORLD_MONITOR_OPENAPI_URL`. Empty defaults mean *not configured* — the
platform never invents a deployment.

### 2.2 Integration package (`app/integrations/world_monitor/`)
| File | Responsibility |
| --- | --- |
| `models.py` | Typed result shapes (`HealthResult`, `DiscoveryStep`, `APIEndpoint`, `DiscoveryResult`) with the closed honest-state vocabulary. |
| `health.py` | One real, scope-guarded `GET`; records status, timing, server/version hints, TLS. `OutOfScopeError` → blocked (never probed). |
| `discovery.py` | Ordered discovery driven **only** by explicit config: base URL → API base → OpenAPI → (metadata/frontend/RPC recorded `unsupported`, never guessed). |
| `provider.py` | `WorldMonitorProvider`: `check_health` / `discover` / `get_api_inventory`. The single boundary the rest of the app talks to. |
| `normalizers.py` | Every fact flows through `app.observations.normalize.build_observation` (normalization **and** redaction choke point) with provenance `source=world_monitor`. |
| `__init__.py` | Exports `WorldMonitorProvider`. |

### 2.3 Persistence (`database/models.py`, Alembic `3d7f5bc81a02`)
- `world_monitor_targets` — one authorized deployment per project
  (`base_url`, optional same-host `api_base_url`/`openapi_url`, connectivity
  `status`, `health_json`, `discovery_json`, `discovered_version`, `error`).
- `world_monitor_api_endpoints` — only really observed endpoints
  (`method`, `path`, `operation_id`, `tags`, `source`, `authentication_hint`,
  optional `observation_id` link), used by the inventory.
- Additive migration, linear chain `2c6e4ab9f71d → 3d7f5bc81a02`;
  `verify_schema()` / `tests/test_schema.py` gate unchanged.

### 2.4 API (`app/api/world_monitor.py`, registered in `app/main.py`)
| Method | Path | Meaning |
| --- | --- | --- |
| POST | `/world-monitor/targets` | Register a deployment (cross-host API/OpenAPI rejected 422). |
| GET | `/world-monitor/targets` | Caller's deployments only. |
| GET | `/world-monitor/targets/{id}` | Detail + inventory; non-owner → 404. |
| DELETE | `/world-monitor/targets/{id}` | Remove deployment + inventory. |
| POST | `/world-monitor/targets/{id}/check` | Real health probe (reachability, never a verdict). |
| POST | `/world-monitor/targets/{id}/discover` | Real discovery; inventory replaced by what was observed. |
| GET | `/world-monitor/targets/{id}/inventory` | Observed API inventory. |

Ownership is the same user → project chain used everywhere; a target that is
not owned is indistinguishable from one that does not exist (404).

### 2.5 Native pipeline tool (`app/orchestration/`)
- `stages.py`: `world_monitor_discovery` → `TARGET_NORMALIZATION`, **conditional**
  (`enabled()` returns true only when the scan references a deployment), so an
  ordinary scan never records a meaningless World Monitor skip.
- `preflight.py` / `app/tools/inventory.py`: recognized as a stdlib/native probe
  (always available, no external binary); skipped from the snapshot when the
  scan does not reference a deployment.
- `executions.py::_run_world_monitor_discovery`: resolves the deployment
  (`target_id` from an owned registered target, or explicit same-host config),
  probes it, persists observations via `build_observation`, and records the
  execution honestly (`skipped` when not configured or disabled).

### 2.6 Cookie security attributes (`§17`)
- `app/http/cookies.py::extract_cookie_attributes` — captures cookie **name +
  flags only** (values discarded at capture time).
- `HTTPResponse.cookies`, populated by `SafeHttpClient`, forwarded by
  `real_probes._http_observations` into `data_json["cookies"]`; `set-cookie`
  values remain `<REDACTED>`.
- New native test `cookies.security_attributes`
  (`app/assess/tests/cookies.py`, registered in `ALL_TESTS`) flags missing
  `HttpOnly` (Low), missing `Secure` over HTTPS (Low) and missing `SameSite`
  (Info).

### 2.7 Scan configuration passthrough
`ScanCreate.world_monitor` (`app/api/scans.py`) and `_merge_config`
(`app/agents/workflow.py`) carry `{"world_monitor": {"target_id": N}}` or an
explicit URL config into the pipeline.

### 2.8 Frontend (`frontend/src/`)
- `pages/NewScan.tsx` — optional **World Monitor deployment** picker (select a
  registered target or register one inline); selection is sent as
  `world_monitor` on scan creation.
- `components/Phase7Console.tsx` — **World Monitor integration** panel: shows
  the scan's WM execution, the caller's deployments with their honest status,
  and `Check` / `Discover` / `Inventory` actions backed by the live endpoints.

## 3. Honest-state contract

Connectivity states are `not_configured | checking | reachable | unavailable |
partially_discovered | discovered`. The integration **never** emits
`secure`/`insecure`; security posture is determined only by assessment findings
derived from persisted observations.

## 4. Tests added

| File | Count |
| --- | --- |
| `tests/test_phase8_config.py` | 3 |
| `tests/test_phase8_world_monitor_provider.py` | 14 (real localhost HTTP fixture) |
| `tests/test_phase8_world_monitor_api.py` | 10 |
| `tests/test_phase8_cookies_security.py` | 13 |
| `tests/test_phase8_world_monitor_discovery_tool.py` | 6 |
| `tests/test_phase8_world_monitor_real.py` | 3 (real pipeline e2e) |
| `tests/test_schema.py` (bumped head + tables) | — |

`execution_platform_version` remains `"phase7"`; Phase 7 contracts (report
fields, SSE/coverage endpoints) are unchanged. **301 passed** (baseline 252).
