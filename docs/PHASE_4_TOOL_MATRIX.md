# Phase 4 — Tool Matrix & Install Verification

**Date:** 2026-09-19
**Repo:** `D:\CyberAgent`
**Phase:** Tool inventory, adapter contract, and honest availability reporting.

## Intent

Every scanner in the CyberAgent pipeline must be *reportable*: what binary it maps to,
whether it is actually installed on the host, its category, and (when available) a real
version string. Reporting is derived from `shutil.which` + a version probe at request
time — never assumed, never fabricated. If a binary is absent the adapter reports
`Not Installed`, and the UI shows exactly that.

## Adapter contract

Shown via `GET /tools/inventory` (authenticated). Each entry:

| Field | Meaning |
|-------|---------|
| `tool` | adapter / pipeline id |
| `binary` | executable name probed on PATH (None for stdlib probes) |
| `installed` | `shutil.which(binary) is not None` |
| `path` | absolute binary path, or null when missing |
| `version` | first line of a successful `<binary> --version` probe, or null |
| `category` | recon / dns / service / http / vulnerability / probe |
| `note` | honest reason when not installed (e.g. `subfinder not found on PATH`) |

## Matrix (as verified live at 2026-09-19, real mode)

| Tool | Binary | Category | Installed (this host) | Version probe |
|------|--------|----------|-----------------------|---------------|
| subfinder | `subfinder` | recon | no | `subfinder -version` |
| assetfinder | `assetfinder` | recon | no | `assetfinder -version` |
| dnsx | `dnsx` | dns | no | `dnsx -version` |
| nmap | `nmap` | service | no | `nmap --version` |
| httpx | `httpx` | http | no | `httpx -version` |
| gau | `gau` | http | no | `gau --version` |
| whatweb | `whatweb` | http | no | `whatweb --version` |
| nuclei | `nuclei` | vulnerability | no | `nuclei -version` |
| real_dns | — (stdlib) | probe | always | — |
| real_tcp | — (stdlib) | probe | always | — |
| real_http | — (stdlib) | probe | always | — |

Live snapshot (scan of `127.0.0.1`): `11` inventory entries, 8 external `installed=false`
(honest), 3 stdlib probes `installed=true`, `simulation_mode=false`.

## How NOT_INSTALLED affects a scan (verified)

- In real mode, an external tool whose binary is missing produces a `ToolResult` row with
  status `Not Installed`; it never fabricates output.
- `Not Installed` tools are **excluded from coverage math** (`compute_coverage` counts only
  *completed* tasks vs planned tasks), so a truncated tool set honestly lowers coverage.
- `completed_tools`/`total_tools` in `GET /scans/{id}` reflect only tools that actually ran.
- Terminal stage is `partial` (status `Partially Completed`) only when `failed_tasks > 0`,
  not merely because coverage < 100%.

## Install to enable a scanner

```powershell
# Example (ProjectDiscovery), then re-open Tool Health on the dashboard:
winget install --id ProjectDiscovery.Subfinder     # or go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# assetfinder: go install github.com/tomnomnom/assetfinder@latest
# dnsx:        go install github.com/projectdiscovery/dnsx/v2/cmd/dnsx@latest
# nmap:        https://nmap.org/download.html
# httpx:       go install github.com/projectdiscovery/httpx/cmd/httpx@latest
# gau:         go install github.com/lc/gau/v2/cmd/gau@latest
# whatweb:     apt install whatweb / https://github.com/urbanadventurer/WhatWeb
# nuclei:      go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

After installation the inventory probe will report the binary + version automatically;
no code change is required.

## Verification

- `GET /tools/inventory` returns honest `installed` flags derived from the live host.
- Frontend `Tool Health` page (`/tools`) renders the inventory, execution mode banner
  (SIMULATION / REAL), and per-tool NOT INSTALLED badges with the reason.
- Backend suite (109 tests) includes `test_tool_inventory_is_honest`, which asserts
  inventory matches `shutil.which` for each binary.