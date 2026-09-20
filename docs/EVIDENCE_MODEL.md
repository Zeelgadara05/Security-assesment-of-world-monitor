# Evidence Model: Capture, Redaction, Hashing & Integrity

**Module:** `app/assess/evidence.py`, `app/assess/poc.py`, `app/reporting/evidence_renderer.py`
**Table:** `FindingEvidence`

## Contract

A finding is only as strong as its retained evidence. Every `FindingEvidence`
row stores enough redacted information to reproduce the reasoning: the request,
the response, the expected vs actual security property, the boundary that was
crossed — plus integrity metadata that makes accidental mutation detectable.

## Columns

| Column | Purpose |
|--------|---------|
| `found_id` → `finding_id`, `observation_id` | Provenance chain |
| `evidence_type` | e.g. `comparison` |
| `request_json` / `response_json` | Redacted payloads (headers scrubbed) |
| `expected` / `actual` / `security_boundary` | The asserted property, redacted text |
| `redaction_status` | Always `"redacted"` |
| `request_hash` / `response_hash` | SHA-256 over canonical JSON of the redacted payload |
| `original_size` / `captured_size` | Bounded-capture bookkeeping |
| `truncated` | True when the persisted body was smaller than observed |

## Redaction (`app/observations/normalize.py`)

`evidence_to_kwargs()` applies the shared redactors before anything is stored:

- `redact_mapping` on request and response payloads (tokens, cookies).
- `redact_headers` on the `headers` sub-map of either payload.
- `redact_text` on `expected`, `actual`, `security_boundary`.

## Bounded capture

`capture_metrics()` implements the `_MAX_EVIDENCE_BODY = 20000` byte ceiling
(matching the HTTP body store limit):

- body absent / non-string → `original_size=None, captured_size=None, truncated=None`.
- body ≤ limit → `truncated=False`, both sizes equal.
- body > limit → `captured_size=20000, truncated=True`; the oversized payload is
  still stored (payload is the JSON body already bounded upstream).

## Hashing & integrity

- `payload_hash(payload)` → SHA-256 of canonical JSON
  (`sort_keys=True, separators=(",", ":"), default=str`). `None` in → `None` out.
- `verify_evidence_integrity(row)` recomputes both hashes over the current stored
  payloads and returns `{"request_ok": bool, "response_ok": bool}`. A `False`
  indicates the stored payload no longer matches its stored hash.
- Hashes are computed over the **redacted** payloads, so integrity covers exactly
  what was persisted.

## Rendering

- `render_evidence(db, finding)` — one dict per record including `integrity`.
- `evidence_markdown_section(rows)` / `evidence_block_markdown` — tables with
  `ok` vs `MISMATCH` verdicts and truncated hashes.
- `GET /findings/{id}/evidence` surfaces the raw request/response proof plus
  integrity verdicts per record.
- The report's `Evidence Trace` section aggregates all records across findings.

## PoC (`app/assess/poc.py`)

`build_poc(db, finding)` derives a deterministic, safety-bound retelling of the
validation: request (method/endpoint/parameter + `request_hash`),
`expected_behavior`/`observed_behavior` (from the first evidence record, falling
back to `validation_reason`), `validation_logic`, the evidence list, and
`SAFETY_CONSTRAINTS` (authorized scope only, minimal request count, no
destruction/harvesting/persistence, SSRF only at the configured callback,
bounded request count). It never invents requests that were not performed.

## Verification

`tests/test_evidence.py` covers: hash stability, None payloads,
`capture_metrics` boundary cases, mutation detection via
`verify_evidence_integrity`, and redaction of headers/tokens.