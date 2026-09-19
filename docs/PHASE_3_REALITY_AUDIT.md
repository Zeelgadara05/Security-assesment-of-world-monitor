# Phase 3 — Reality Audit (Findings Pipeline)

**Date:** 2026-09-19
**Scope:** every behavior in the finding lifecycle (recon → observations → evidence →
rule engine → triage/dedup → score → persisted findings → report → dashboard) is
classified as REAL / SIMULATED / HARDCODED / MOCK / TEMPLATE / PLACEHOLDER / DEAD
CODE with an action and reason.

Legend:
- **REAL** — genuine behavior backed by code + real data (no substitution).
- **SIMULATED** — synthetic output explicitly produced and explicitly marked; never
  presented as real.
- **HARDCODED** — fixed literal baked into source.
- **MOCK** — fake stand-in that previously faked a real capability.
- **TEMPLATE** — static skeleton/content; makes no live-data claim.
- **PLACEHOLDER** — clearly-labeled stand-in that is not persisted or functional.
- **DEAD CODE** — unreachable/unreferenced after Phase 3 changes.

| Location | Behavior | Classification | Action | Reason |
|---|---|---|---|---|
| `backend/app/tools/scanner_tools.py` `NucleiAdapter.simulate()` (old) | Invented SQLi (Critical), jQuery (Medium), CSP (Low) findings per target | HARDCODED / FABRICATED | **REMOVED** | Root cause of fake score (64/100). Never a real scan |
| `backend/app/tools/scanner_tools.py` `NucleiAdapter.simulate()` (new) | Returns `vulnerabilities: []`; raw_output explains simulation and that no findings are produced | SIMULATED | Keep | Simulation path is a documented zero-findings baseline (score 100) |
| `backend/app/agents/workflow.py` (old) | Wrote `nuclei_res["vulnerabilities"]` into the DB verbatim → fabricated findings persisted | MOCK / DEAD | **REWRITTEN** | Analysis now runs only on persisted observations |
| `backend/app/api/chat.py` (old) | Canned replies about "CVE-2024-38494", "CVE-2015-9251", "detected vulnerabilities" | HARDCODED / FABRICATED | **REWRITTEN** | Assistant now answers only from persisted findings (or states none exist) |
| `backend/app/tools/real_probes.py` `dns_probe` | stdlib DNS resolution of a real host; result persisted verbatim | REAL | Keep | No synthetic IPs; `dns_error` observation when resolution fails |
| `backend/app/tools/real_probes.py` `tcp_probe` | `socket.create_ex((host, port))` connect attempt over a fixed port list | REAL | Keep | `tcp_open` only when connect succeeds; `tcp_closed` otherwise |
| `backend/app/tools/real_probes.py` `http_probe` | `urllib` GET; extracts status/title/server/header flags/version hint/body snippet | REAL | Keep | `http_response` only on real reply; `http_error` with OS reason recorded verbatim |
| `backend/app/tools/real_probes.py` `body_match_observation` / `extract_jquery_version` | Parses only when a jQuery/`jquery` version string is actually present | REAL | Keep | Version-driven finding cannot fire without version evidence |
| `backend/app/assess/finding_rules.py` `evaluate_observations` | Rule engine converts persisted observations to candidate findings | REAL | Keep (tested) | No observation ⇒ no candidate |
| `backend/app/assess/finding_rules.py` `missing-security-header` | Low, CVSS 3.1, CWE-693; requires an `http_response` with the flag absent | REAL | Keep (tested) | HSTS marked present on `http://` is not penalized |
| `backend/app/assess/finding_rules.py` `server-version-banner` | Info, CWE-200; requires a version/hint string in evidence | REAL | Keep (tested) | No banner version ⇒ no finding |
| `backend/app/assess/finding_rules.py` `outdated-jquery` | Medium, CVE-2015-9251; only for version < 3.7.0 | REAL | Keep (tested) | Modern versions (≥3.7.0) are clean |
| `backend/app/assess/finding_rules.py` `nuclei-reported-finding` | Re-uses real nuclei engine output (when installed) as an evidence-backed observation | REAL | Keep | Real engine output only; never invented |
| `backend/app/assess/finding_rules.py` `deduplicate` / `compute_score` | Dedup vs persisted open `dedup_key`s; score 100 − Σ weights (Critical 25/High 15/Medium 8/Low 3/Info 0), floor 10; resolved states excluded | REAL | Keep (tested) | Triage-adjusted score |
| `backend/app/api/findings.py` `POST /findings/{id}/triage` | State transitions confirm/false_positive/duplicate/accepted_risk/resolve; ownership via `get_owned_scan` | REAL | Keep (tested) | No automatic CONFIRMED; only the listed actions |
| `backend/app/api/scans.py` `/scans/summary` | Real counts from persisted, user-owned rows (open findings, severity distribution, open ports, score history) | REAL | Keep (tested) | Dashboard data source |
| `backend/app/api/scans.py` details (added fields) | `state, rule_id, confidence, cwe, evidence, evidence_observation_ids, resolved_at` | REAL | Keep | Lets UI surface evidence trails |
| `backend/app/agents/workflow.py` report stage | Markdown/HTML/JSON built **only** from persisted findings and observations | REAL (downstream) | Keep | Report cannot invent data |
| `backend/app/agents/workflow.py` `pdf_content` | Stored bytes are the markdown source labelled pdf/mock (unchanged from Phase 2) | MOCK (documented) | Keep | Real PDF generator out of scope |
| `frontend/src/pages/Dashboard.tsx` (old) | Hardcoded trend data, severity pie, ports chart, and count **10** | HARDCODED / MOCK | **REPLACED** | Now renders `/scans/summary`; empty states when no data |
| `backend/app/tools/scanner_tools.py` external adapters | `shutil.which` availability on this machine | REAL | Keep | Honest NOT INSTALLED; never fakes tool output |
| `backend/database/` `Observation` model + migration `8f3a2c51d94e6b77` | New persisted observation + evidence schema | REAL | Keep | Single source of truth for findings |
| Simulation-mode workflow | 0 observations, 0 findings, score 100 baseline; `[SIMULATION]` log lines | SIMULATED | Keep (tested) | Explicitly labeled, never presented as a real assessment |

## Findings traceability (REAL path)

```
authorized target -> real_probes (dns/tcp/http) + real nuclei (if installed)
   -> Observation rows (persisted, verbatim, evidence)
   -> finding_rules.evaluate_observations (rule_id + observation_ids)
   -> deduplicate against persisted open dedup_keys
   -> Vulnerability rows (state=NEW, evidence text, evidence_observation_ids)
   -> triage (confirm/false_positive/duplicate/accepted_risk/resolve)
   -> compute_score (weighted, resolved states excluded)
   -> report + dashboard (/scans/summary), strictly downstream
```

## Remaining simulated / mock / placeholder surface

- External scanner binaries (subfinder, nmap, nuclei, …) are **NOT INSTALLED** on this
  machine — every adapter reports that honestly; nothing invents results.
- `pdf_content` remains the markdown source as a documented mock (out of scope).
- Chat assistant is not an LLM; it is a data-driven rule assistant that answers from
  persisted findings and is still flagged `"simulated": true` in responses.
- **Known open item:** discovered subdomains are re-checked against the authorized
  scope before being probed downstream. With no scanner binaries installed here the
  practical probe list is `[target]` only, but full re-validation is a documented
  follow-up before enabling real subdomain discovery.

## Report unification

Every metric that previously depended on fabricated or hardcoded data now derives
from persisted rows owned by the authenticated user (`/scans/summary`,
`/scans/detail`, `/reports`, chat profile). There are **no fabricated findings,
no hardcoded dashboard counts, and no canned "vulnerability" answers** remaining in
shipped code.