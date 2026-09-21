# Phase 8 — Reality Audit

**Date:** 2026-09-21
**Scope:** Phase 8 as implemented vs `docs/PHASE_8_IMPLEMENTATION.md`. Every
claim below was checked by running the real pipeline (real probes over real
sockets, no mocked HTTP in the integration path), reading source, exercising the
live API, and running the full test suite.

## Verdict: IMPLEMENTED and honest

Full backend suite: **301 passed** (baseline 252). Frontend `tsc` + `vite build`
pass. Phase 8 adds **49 tests across 6 new files**. Live API verified against a
running backend (see §Live verification).

## IMPLEMENTED

1. **Configuration** — `WORLD_MONITOR_{BASE_URL,API_BASE_URL,OPENAPI_URL}`
   default to empty; `test_world_monitor_urls_are_never_guessed` asserts no
   placeholder URLs exist.
2. **Integration package** — `provider`, `health`, `discovery`, `normalizers`
   are real and unit/integration tested against a localhost
   `ThreadingHTTPServer` fixture (14 provider tests). Health treats every HTTP
   status as *reachable* (no verdict); redirects into scope are followed, out of
   scope are **blocked** (`OutOfScopeError` → `blocked`, never a fake failure).
3. **No guessed endpoints** — `test_discover_without_openapi_never_guesses`,
   `test_discover_empty_base_is_not_configured`,
   `test_discover_rejects_non_json_openapi`: discovery returns `[]` /
   `not_configured` rather than inventing routes.
4. **Persistence** — additive migration `3d7f5bc81a02`; `tests/test_schema.py`
   asserts head, the two tables, and the model/status constants. Startup
   `verify_schema()` unchanged (fails loudly, no `create_all`).
5. **API** — `/world-monitor/*` router; 10 tests cover auth, invalid URL,
   cross-host rejection (`422`), create/list/get/delete, ownership `404`,
   reachable/unreachable check persistence, and honest discovery.
6. **Pipeline tool** — 6 tests: honest `not_configured` skip, explicit-config
   real probe + persisted observations, registered-target reference, cross-host
   refusal, out-of-scope redirect recorded (not followed), preflight native-probe
   classification.
7. **Real pipeline e2e** — 3 tests via `orchestrate_scan_phase7(simulation=False)`
   against a localhost fixture (explicit config, registered target, and
   unconfigured-never-plans). Confirmed the WM observation reaches the store.
8. **Cookie security attributes** — 13 tests; `extract_cookie_attributes`
   provably contains **no values**, redaction keeps `set-cookie` `<REDACTED>`,
   and `cookies.security_attributes` flags missing flags without inventing a
   verdict.
9. **Frontend** — WM picker in `NewScan.tsx` and WM panel in
   `Phase7Console.tsx` compile and build.
10. **Race hardening** — `app/api/scans.py` now commits/refreshes the freshly
    queued scan **before** launching the worker, so `POST /scans` reports the
    true queued stage. (This was a latent Phase 4 timing race; see §Follow-ups.)

## Live verification (real backend, real sockets)

Backend restarted on `127.0.0.1:8001` (PID 10812); `/docs` → `200`. A fresh
user registered, then:

| Step | Result |
| --- | --- |
| `POST /world-monitor/targets {base_url}` | `id=1 status=not_configured` (registered, not yet probed) |
| `GET /world-monitor/targets` | `count=1` |
| `POST /world-monitor/targets/1/check` | `status=reachable http=200` |
| `GET /world-monitor/targets/1/inventory` | `endpoints=0 status=reachable` |
| `DELETE /world-monitor/targets/1` | `deleted=True` |

`endpoints=0` is the **correct honest outcome**: the target was configured with
a base URL only and no OpenAPI, so no endpoints were guessed.

## PARTIALLY_IMPLEMENTED

1. **External World Monitor deployment** — no real, separately-deployed World
   Monitor instance is available in this environment. The integration is proven
   against a spec-shaped localhost fixture and a live local backend, but a scan
   of a production World Monitor has not been demonstrated here. This is an
   environment limitation, not a code path: the provider is real and
   scope-guarded.
2. **API inventory richness** — inventory is populated only from a real OpenAPI
   document. Without one, it is empty by design. GraphQL/RPC/metadata/frontend
   surfaces are recorded `unsupported`, not probed.

## BLOCKED_BY_ENVIRONMENT

1. No external World Monitor host/reachability was available; same for the real
   external binaries noted in Phase 7. The pipeline handles absence honestly.
2. No ML weights: AI remains `advisory_only` (`model_name=None`) — unchanged
   from Phase 7.

## NOT_IMPLEMENTED

1. Nothing on the Phase 8 contract. Kafka (spec §20) remains N/A — there is no
   Kafka anywhere in this repository.

## Follow-ups (non-blocking)

- `POST /scans` had a latent timing race where the background worker could
  advance a scan's stage before the create response serialized (observed as a
  flaky `test_post_scans_queues_immediately_with_config_and_reaches_completed`).
  Fixed by committing/refreshing the queued row before `trigger_background_scan`;
  the full suite is green after the fix.
- `datetime.utcnow()`, fastapi `on_event`, and SQLAlchemy legacy warnings are
  cosmetic and intentionally unchanged (repo-wide style).
- Two JSON report shapes (`reports.json_content` vs `builder.build()`) remain
  as documented in `PHASE_7_ARCHITECTURE.md`; out of Phase 8 scope.

## §40 Final report

**Phase 8 regression:** PASS — full backend suite **301 passed / 0 failed**
(baseline 252; +49 net). Frontend `tsc` + `vite build`: PASS. Live API on
`127.0.0.1:8001`: PASS (see §Live verification).

**Totals**
| Metric | Value |
| --- | --- |
| Backend tests | 301 passed |
| Phase 8 test files | 6 |
| Phase 8 tests | 49 |
| Phase 8 migrations | 1 (`3d7f5bc81a02`, additive) |
| Phase 8 tables | 2 (`world_monitor_targets`, `world_monitor_api_endpoints`) |
| Phase 8 API routes | 7 |
| `execution_platform_version` | `"phase7"` (unchanged) |

**World Monitor IMPLEMENTED items (1–10):** configuration; integration package
(provider/health/discovery/normalizers); no-guess discovery; persistence +
migration; `/world-monitor/*` API with ownership isolation; native pipeline tool
with honest `not_configured`/blocked handling; real pipeline e2e; cookie
security attributes; frontend picker + console panel; `POST /scans` race
hardening.

**Integrity counters**
| Counter | Value | Evidence |
| --- | --- | --- |
| Hardcoded findings | **0** | `PHASE_8_BASELINE_AUDIT.md` §"Fake findings" audit; only static educational copy in `KnowledgeBase.tsx` / `AIChat.tsx`. |
| Fabricated / guessed endpoints | **0** | `test_discover_without_openapi_never_guesses`, live `inventory endpoints=0` for a base-URL-only target. |
| Evidence-less findings | **0** | `tests/test_phase7_real_local_scan.py:163` asserts every finding cites persisted scan observations; still green. |
