# Phase 9 — Reality Audit (independent re-verification)

**Date:** 2026-09-22
**Method:** run the shipped suite and the §49/§50 acceptance trio, then
re-derive each claimed behaviour from the authoritative implementation and the
test/DB rows — **never** from the docs, the spec tiles, or my own prose. If a
claim could not be shown from a real persisted row or a real HTTP response, it
is not written here.

---

## 1. What "reality" means for this Phase

The capstone's one unforgiving rule is that **no observation ⇒ no finding**, so
reality here is measured the same way:

1. **Nothing invented.** Every number, asset, finding and event in the shipped
   UI must trace back to a persisted row owned by the caller.
2. **Honest vocabulary.** Statuses stay `not_configured/checking/…`, gaps stay
   gaps, and assets/findings are only ever surfaced when a real row exists.
3. **Only one evidence path.** The real pipeline emits assets and granular
   events only *after* the underlying row was flushed to the database.

This audit re-derives that evidence chain from the ground up, using the exact
commands an operator (or an external auditor) can run tomorrow.

---

## 2. Re-verification ledger

| # | Claim (what an operator sees) | Where it is guaranteed | Re-checked how |
| --- | --- | --- | --- |
| A1 | `GET /scans/{id}/observations` returns persisted observations only, each with its persisted `id` and `asset_id` | `backend/app/api/scans.py` (`get_scan_observations`) + `tests/test_phase9_granular_events.py::test_typed_events…` | Test asserts every row has `observation_id`/`asset_id` populated from DB columns, never hardcoded |
| B1 | `GET /scans/{id}/assets` returns a deduplicated host→endpoint graph with real `parent_asset_id` edges | `backend/app/api/scans.py` (`get_scan_assets`) + asset graph population in the pipeline | Test seeds host+endpoint rows with `parent_asset_id`, asserts endpoint child + sorted children + matched observation `asset_id`, and that a second population pass creates **no** new rows |
| C1 | Typed event stream (`/scans/{id}/typed-events`) replays the granular chain `observation.created → asset.discovered → … → finding.verified` in `seq` order with persisted ids | `backend/app/orchestration/events.py::replay` + `tests/test_phase9_granular_events.py` | Test asserts event order by `seq`, unique ascending seqs, and that observation events carry persisted `observation_id`s |
| D2 | Findings triage writes an immutable, timestamped verdict history that `GET /findings/{id}` replays in order (`actor`, `reason`, from/to status) | `backend/app/assess/finding_lifecycle.py` + `tests/test_phase9_dashboard.py` (`test_finding_triage_append_history…`) | Test walks the timeline, asserts monotonic ids, actors, and that the latest verdict is a real row in `FindingStatusHistory` |
| E1 | `GET /reports/list` surfaces `content_hash`, registry config fingerprints, `has_html`/`has_pdf`/`has_markdown` flags and exported length per scan | `backend/app/api/reports.py` (`list_reports`) + `tests/test_phase9_report_exports.py` | Test asserts SHA-256 hash/fingerprints/length from a persisted `ReportExport` row |
| F1 | Dashboard aggregates come from persisted summary rows (coverage trend, counts) not sample figures | `tests/test_phase9_dashboard.py::test_dashboard_relies_only_on_persisted_rows…` | Test seeds observations/findings/assets and asserts the snapshot derives every counter strictly from those rows |

## 3. End-to-end trace, §49-style (the five links)

1. **Observation rows are created** by the real probes (`dns_record`,
   `http_response`, …). Their `kind`, `subject`, `data_json` are what the
   operator sees in the workspace. *Only after `db.flush()`* →
2. **`observation.created` event** is persisted with the observation's id →
3. **The asset graph** is populated: host/endpoint `Asset` rows are linked to
   every observation via `asset_id`, and `asset.discovered` events record the
   new asset ids → 4. **findings** (`finding.candidate`/`finding.verified`)
   reference only those persisted observations → 5. **workspace + dashboard +
   report** render from those same persisted rows.

Every intermediate is a real, persisted row. There is no path in the shipped
code where a number is pulled from a constant, a random call, or the spec.

---

## 4. Commands to reproduce this audit

```
cd backend
venv\Scripts\python.exe -X dev -W ignore -m pytest tests\test_phase9_granular_events.py \
        tests\test_phase9_dashboard.py tests\test_phase9_report_exports.py -q
# -> 9 passed

# whole Phase 9+ platform regression:
venv\Scripts\python.exe -X dev -W ignore -m pytest tests -q
# -> 333 passed
```

The 333-passing run (measured 2026-09-22) is the honest baseline for the
Phase 9 capstone surface: assets, observations, granular events, triage
history, report exports and the §50 dashboard — all pinned by tests that seed
real rows and assert against real API responses.

---

## 5. Remaining honest caveats

* **Frontend §63 "World Monitor" page is routed but not yet exercised by a
  dedicated contract test.** The World Monitor *register/check/delete* API is
  covered by its own Phase 8 test file; the acceptance trio above covers the
  shared pipeline, report and finding surfaces. The page itself was added as
  additive UI (no regression to the 333 baseline).
* The **typed-events payload shape** is `{"cursor", "has_more", "events":[…]}`;
  the granular replay test pins the exact ordering contract, so an API change
  that reorders or renames events fails the trio rather than silently drifting.
* The **legacy `Report` (in-scan artifact) and `ReportExport` (hash) stores
  coexist by design**; `list_reports` merges the latest export hash onto each
  report row, which the report-exports test verifies.

Anything not in this ledger is out of scope for Phase 9 by construction — the
Phase 9 design (see `PHASE_9_ARCHITECTURE.md`) extends only the real evidence
path and never a second, simulated one.
