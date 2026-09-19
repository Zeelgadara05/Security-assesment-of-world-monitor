# Phase 2 — Reality Audit

**Date:** 2026-09-19
**Scope:** every behavior touched or inspected during Phase 2 is classified as
REAL / SIMULATED / HARDCODED / MOCK / TEMPLATE / PLACEHOLDER / DEAD CODE with an
action and reason.

Legend:
- **REAL** — genuine behavior backed by code + data (no substitution).
- **SIMULATED** — synthetic output explicitly produced and explicitly marked; never
  presented as real.
- **HARDCODED** — fixed literal baked into source.
- **MOCK** — fake stand-in that previously faked a real capability.
- **TEMPLATE** — static skeleton/content; makes no live-data claim.
- **PLACEHOLDER** — clearly-labeled stand-in that is not persisted or functional.
- **DEAD CODE** — unreachable/unreferenced; removed in Phase 1.

| Location | Behavior | Classification | Action | Reason |
|---|---|---|---|---|
| `backend/app/api/auth.py` (register/login/logout/me/ profile, sessions) | PBKDF2-hashed passwords, opaque revocable session tokens, digest-only storage | REAL | Keep (tested: `test_auth.py`) | New zero-dependency auth core |
| `backend/database/connection.py` `seed_defaults()` | Bootstrap admin only when `ADMIN_*` set; otherwise no auto-provisioned accounts | REAL (config-driven) | Keep | Prevents unauthenticated default access |
| `backend/database/connection.py` (old) | Implicit demo user `demo@cyberagent.ai` + fixed password | HARDCODED / MOCK | **REMOVED** in Phase 2 | Violates no-demo-account rule; legacy rows left as history only |
| `backend/app/api/auth.py` (old) | Returned a fake "always authenticated" user on every request | MOCK | **REPLACED** with real dependencies | Was the §5.7 audit finding |
| `backend/app/core/security.py` | `pbkdf2_hmac("sha256")`, 600k iterations | REAL | Keep | Stdlib-only, no new deps |
| `backend/app/core/auth.py` `is_target_in_scope` / `get_owned_scan` | Ownership chain users→projects→scans→children; foreign objects → 404 | REAL | Keep (tested: `test_authorization.py`, `test_scope.py`) | Server-side isolation |
| `backend/app/core/auth.py` `require_admin` | `/auth/users`, `/auth/admin/overview` gated by role | REAL | Keep (tested: `test_rbac.py`) | RBAC foundation |
| `backend/app/tools/scanner_tools.py` `simulate()` | Synthetic findings emitted only under an explicit simulation flag | SIMULATED | Keep | Marked `[SIMULATED]` downstream |
| `backend/app/tools/scanner_tools.py` adapters | `shutil.which` availability; NOT INSTALLED / TIMEOUT / EXECUTION FAILED / PARSE FAILED states | REAL | Keep (tested: `test_scanner_adapters.py`) | Foundation for real tools; never invents results |
| `backend/app/tools/scanner_tools.py` `sanitize_input` + `shell=False` lists | Injection-safe argument lists | REAL | Keep | Defense for real-execution path |
| `backend/app/agents/workflow.py` `save_tool_result` | Adapter state→persisted status mapping; `[SIMULATED]` prefix for simulated rows | REAL (mapping) + SIMULATED (marker) | Keep | State mapping tested in `test_tool_simulation_markers.py` |
| `backend/app/api/chat.py` | Keyword-driven deterministic assistant (no LLM) | SIMULATED | Keep; response includes `"simulated": true` | Honest labeling; history ordering bug fixed (`.asc()`) |
| `backend/app/api/reports.py` `/reports/{id}/pdf` | Serves stored report bytes as `application/pdf`; docstring states simulated | MOCK / SIMULATED | Document as limitation; real PDF generator deferred | ReportLab/Weasyprint not in scope |
| `backend/app/api/scans.py` `/scans/trigger` | 403 for out-of-scope targets via `is_target_in_scope` | REAL | Keep (tested: `test_scope.py`) | Scope enforcement |
| `backend/database/schemas.py` `normalize_target` | Lowercase normalization shared by validator + scope | REAL | Keep | Consistent scope matching; tested |
| `backend/app/main.py` | CORS explicit origins + `allow_credentials=True` | REAL | Keep | Required for token flows from the SPA |
| `frontend/src/pages/Auth.tsx` | Real `/auth/login` + `/auth/register`; server errors surfaced | REAL | Keep | Replaces mocked Supabase flow |
| `frontend/src/pages/Auth.tsx` (old) | `setTimeout` fake auth + session marked active locally | MOCK | **REPLACED** | Was §5.9 mock-auth finding |
| `frontend/src/App.tsx` (old) | `localStorage.cyberagent_session === 'active'` pseudo-auth | MOCK | **REPLACED** with stored token + 401 logout | Real session lifecycle |
| `frontend/src/layouts/DashboardLayout.tsx` (old) | Hardcoded "SecAdmin" / `demo@cyberagent.ai` / "SA" | MOCK | **REPLACED** with `/auth/me` | Fabricated identity removed |
| `frontend/src/pages/Settings.tsx` | `sk-…` / `gsk_…` / `sh_…` strings, fake "Settings Saved" toast | PLACEHOLDER (documented) | Kept as read-only placeholders; save + toast removed; copy states keys are unused | No credentials stored client-side |
| `frontend/src/pages/Dashboard.tsx` | Static `trendData`, `severityPieData`, `portsData`; hardcoded count `10` | MOCK / TEMPLATE | Left as sample visuals; documented here (not derived from live data) | Chart polish out of Phase 2 scope |
| `frontend/src/pages/KnowledgeBase.tsx` | Static educational content | TEMPLATE | Keep | No live-data claims |
| `frontend/src/pages/NewScan.tsx` / `api.ts` | SSE via `?token=`, `apiFetch` bearer header, 403/401 UX | REAL | Keep | EventSource cannot set headers |
| `frontend/src/pages/Reports.tsx` | Download links carry token query param | REAL | Keep | `<a download>` cannot set headers |
| `backend/cyberagent.db` legacy rows | Pre-Phase-2 demo user with `password_hash = NULL` | DEAD / historical | Left as historical rows, cannot authenticate | No credential fabrication |

## Summary

- All **MOCK/HARDCODED** auth surface removed or replaced with real implementations.
- Remaining **SIMULATED / MOCK / PLACEHOLDER / TEMPLATE** items are either explicitly
  marked, explicitly documented, or otherwise unable to impersonate a real capability.
- **No demo account, no hardcoded credentials, no fabricated scanner output, and no
  "always-authenticated" fallback remain in shipped code.**