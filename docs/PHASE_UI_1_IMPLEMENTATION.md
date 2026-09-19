# PHASE UI-1 — Frontend UI/UX Redesign

## Scope

A frontend-only redesign of the CyberAgent React SPA: a professional security-operations
dashboard for the scan platform. No backend, API-contract, database, authentication-rules,
or workflow changes were made. No new dependencies were introduced. All pages keep reading
the same endpoints through `frontend/src/api.ts`.

## Constraints honored

- No invented data: every table, stat, graph, and chat answer renders live API responses or
  explicit empty/loading/error states.
- Real-time flows preserved: SSE tool logs / scan events still use `authUrl()` event sources.
- Existing icon library only (`lucide-react`), existing fonts (Fira Sans + Fira Code), and
  no new framework or state library.
- Emoji-free, gradient-free, glassmorphism-free. Single restrained emerald accent.

## Design system

`frontend/src/index.css` (Tailwind v4 CSS-first config replaced inline ampersands with real
tokens):

| Token | Value |
| --- | --- |
| `bg` | `#0a0b0d` |
| `surface` / `surface-2` | `#101214` / `#15171b` |
| `line` / `line-strong` | `#26282d` / `#36393f` |
| `text` / `muted` / `faint` | `#e7e7ea` / `#a1a6ae` / `#71767d` |
| `accent` / `accent-strong` | `#10b981` / `#059669` |
| severity | critical `#ef4444`, high `#f97316`, medium `#eab308`, low `#3b82f6`, neutral `#8b929a` |

Utilities added: `.panel`, `.panel-2`, `.eyebrow` (mono uppercase label), `.mono-cell`,
`.tbl` (data-table styling), `.dot`/`.dot-ok`/`.dot-warn`/`.dot-danger`/`.dot-neutral`
(live status dots with pulse), `.skeleton` shimmer, focus-visible rings, custom scrollbar,
`prefers-reduced-motion` handling. The old `glass-card` utility was removed.

## New shared components (`frontend/src/components/`)

- `Button.tsx` — Button (primary/secondary/outline/ghost semantics, sm/md/lg) + IconButton.
- `Field.tsx` — themed Input/Select with optional label + hint.
- `StatusBadge.tsx` — status → tone/label mapping, incl. `pending` → active tone.
- `SeverityBadge.tsx` — severity → color mapping (Badge + plain Text).
- `DataTable.tsx` — generic typed table with loading, empty, error, and row-click handling.
- `EmptyState.tsx`, `ErrorState.tsx` — contextual empty/loading/error blocks.
- `Skeleton.tsx` — row/table/panel skeletons.
- `PageHeader.tsx` — consistent page header (eyebrow, title, description, actions, meta).
- `format.ts` — date/time/relative/duration/truncation/pluralization helpers.

## Application shell (`frontend/src/layouts/DashboardLayout.tsx`)

- 52px top operational bar: brand mark, execution-mode chip (Live/Simulation from
  `/tools/inventory`), user session (from `/auth/me`) with logout, mobile menu toggle.
- 220px sidebar grouped into **Operations** (Overview, New Assessment, Assessments, Assets,
  Reports), **Intelligence** (Assessment Assistant, Tool Health), and **Workspace**
  (Knowledge Base, Settings) with active-page indicator.
- Authorized-scope context block from `/scans/scope` (declared scope + count, honest
  "No scope declared" empty state).
- Mobile drawer navigation; group/route transitions via `framer-motion` `AnimatePresence`
  (fade + slight translate, disabled under `prefers-reduced-motion`).

## Pages

- **Auth** — split-screen brand panel + credential form. No fabricated marketing; honest
  tagline about scope-gated, evidence-backed scanning. Success/failure states surfaced
  on screen, token stored via existing `setToken`.
- **Dashboard** — four stat tiles (assessments run, open findings, avg security score,
  open ports) from `/scans/summary`, security score bars from `score_history`, severity
  distribution, recent assessments table (row-click → scan detail) from `/scans/list`.
- **New Assessment** — target + severity + profile + tool-select grouped by category,
  scope manager (view/update via `/scans/scope`), SSE log panel with cancel, then a
  commit summary. No invented tool descriptions.
- **Assessments** — selectable scan list, header summary, per-scan lifecycle timeline
  (stage chips, no fake "running" pulse), tool pipeline with installed/unavailable states,
  findings accordion with evidence provenance and PoC, live events and logs (SSE), cancel.
- **Assets** — topology graph (`@xyflow/react`) plus a dense asset table from
  `/auth/assets` with severity counts and updated times.
- **Reports** — report list, Monaco preview (md/json/html), format selector, and download
  links (markdown/json/pdf via `authUrl`).
- **Assessment Assistant** — scan-session picker, chat history (`/chat/history/{id}`),
  send flow (`/chat/query` with `chat/query`), sample questions wired to real
  `sendMessage`, loading state.
- **Tool Health** — `/tools/inventory` grid with mode banner and re-probe.
- **Knowledge Base** — static, but re-styled to match the system (no fake data claims;
  references real product behavior).
- **Settings** — session/user details from `/auth/me`; re-styled without fake controls.

## Validation

- `npm run build` (`tsc && vite build`) passes clean.
- All API integrations verified against the live backend (port 8003):
  `/auth/login`, `/auth/me`, `/scans/summary`, `/scans/list`, `/scans/scope`,
  `/tools/inventory`, `/auth/assets`, `/reports/list`, `/scans/20` detail shape.
- No leftover `glass-card`, gradient, or gold/rose color classes in `src/`.

## Known limitations

- `noUnusedLocals` is off in `tsconfig`; a few imports were clean, but TS won't error on
  unused ones. Manually swept; no ESLint script exists in `package.json`.
- Build warning (unchanged): the main bundle exceeds 500 kB due to Monaco; accepted
  for this phase, code-splitting left as a future optimization.
- `tailwind.config.js` is legacy/no-op under Tailwind v4 CSS-first config; left untouched
  to minimize risk.
- Chat answers are limited to persisted evidence (deterministic); no live "under-the-hood"
  synthesis beyond what the backend already returns.

## Files changed (frontend only)

- `frontend/index.html` — title → "CyberAgent · Scan Platform"
- `frontend/src/index.css` — new design tokens + utilities
- `frontend/src/layouts/DashboardLayout.tsx` — new shell + navigation
- `frontend/src/pages/**` — all ten pages redesigned (Auth, Dashboard, NewScan, Scans,
  Assets, Reports, AIChat, ToolHealth, KnowledgeBase, Settings)
- `frontend/src/components/**` — new shared primitives (Button, Field, StatusBadge,
  SeverityBadge, EmptyState, ErrorState, Skeleton, PageHeader, DataTable, format)