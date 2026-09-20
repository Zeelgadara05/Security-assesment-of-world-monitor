# Finding Lifecycle & Immutable History

**Module:** `app/assess/finding_lifecycle.py`, `app/api/findings.py`

## Statuses

`candidate ≠ vulnerability`. A `candidate` is unconfirmed potential; only
`confirmed` is a reportable vulnerability.

| Status | Meaning |
|--------|---------|
| `candidate` | Potential finding (e.g. swept external tool output), not yet validated |
| `validated` | Deterministic validator exercised, awaiting confirmation |
| `confirmed` | Full evidence chain satisfied; reportable |
| `rejected` | Validated then disproven (false positive) |
| `duplicate` | Same fingerprint as an existing finding |
| `accepted` | Operator accepts the residual risk |
| `remediated` | Verified fixed/resolved |
| `reopened` | Previously resolved/rejected/duplicate, resurfaced |

## Transition graph

```
candidate  -> validated, rejected, duplicate, accepted, confirmed
validated  -> confirmed, rejected, duplicate, accepted
confirmed  -> accepted, remediated, duplicate, reopened
accepted   -> remediated, reopened, duplicate
remediated -> reopened
rejected   -> reopened
duplicate  -> reopened
reopened   -> candidate, confirmed, rejected
```

- Illegal jumps raise `InvalidTransition` (surfaced as HTTP 400 by the triage API).
- `is_terminal()` is true only for `accepted` and `remediated`.
- Engine-created findings start at `confirmed` with
  `record_initial(... from_status="none")`.

## Immutable history

Every row in `finding_status_history` records `from_status`, `to_status`,
`actor`, `reason`, `created_at`. History is append-only: it is never updated,
deleted, or reordered. The initial engine creation is itself a history row.

```python
lifecycle.transition(db, finding, lifecycle.STATUS_REMEDIATED,
                     actor="analyst@corp", reason="verified fixed in 2.3.1")
```

- `transition()` refuses `from_status == to_status` and unknown statuses.
- `apply_external_status()` whitelists legacy phase-3 spellings
  (`FALSE_POSITIVE`, `DUPLICATE`, `ACCEPTED_RISK`, `RESOLVED`).

## Triage API

`POST /findings/{id}/triage` with `{"action": <action>, "reason": <optional>}`:

| Action | Lifecycle status | Legacy `state` |
|--------|------------------|----------------|
| `confirm` | confirmed | CONFIRMED |
| `false_positive` | rejected | FALSE_POSITIVE |
| `duplicate` | duplicate | DUPLICATE |
| `accepted_risk` | accepted | ACCEPTED_RISK |
| `resolve` | remediated | RESOLVED |

The legacy Phase 3 `state` column is kept in sync so existing score/charts keep
working. `remediated` sets `resolved_at`; ownership is enforced through
scan → project → user (a foreign finding is indistinguishable from missing).

## Reads

- `GET /findings/{id}` returns status, state, `cvss` block, `proof_of_concept`,
  `evidence`, `history` (with redacted reasons via `safe_text`).
- `GET /findings/{id}/evidence` returns request/response proof with per-row
  integrity verdicts.

## Verification

`tests/test_finding_lifecycle.py` covers: legal chains, illegal transition
rejection, immutable history append behavior, `reopened` from every terminal
state, resolving sets `resolved_at`, and legacy state sync aliases.