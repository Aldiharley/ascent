# Ascent Console "Watchdog" UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-skin and re-lay-out the Ascent Console in the "Watchdog" clay-and-fabric theme from the user's two references, with the white fluffy watchdog mascot, without changing any function or backend.

**Architecture:** Frontend only (`frontend/`). The design spec `docs/superpowers/specs/2026-10-31-ui-redesign-design.md` is the source of truth for every value (tokens, layouts, component specs, copy, contrast pairs, responsive modes, test updates). Each task below implements named spec sections, ends green, and keeps every existing behaviour. The spec's section 0 "Non-negotiables" bind every task.

**Tech Stack:** React 18 + TypeScript + Vite + vitest + plain CSS; Google Fonts (Nunito, Plus Jakarta Sans, JetBrains Mono). No new npm dependencies.

## Global Constraints

- Spec §0 non-negotiables, verbatim in force: scanned data renders as React text only (no `dangerouslySetInnerHTML`, no `rehype-raw`; class names/colours/icons from fixed lookup tables keyed by enums); **no `<img>` element** in any data-rendering component — all mascot/texture art is a CSS `background-image` on an `aria-hidden` element; the sentence "Every decision is written to the audit log. Approving records consent; it does not run the command." stays visible under every Approve button; the policy card says "Read-only verdict from out/gate.json"; New Scan keeps "defines scope — does not launch", the "Creating a scan writes a scope file…" note and the copyable `ascent run …` command; the hero CTA reads "Define a new scan" (never Start/Run); CSP unchanged; no inert controls.
- No backend change, no new endpoint, no new npm dependency, no feature removed.
- Assets are already generated and must be used as-is: `frontend/public/mascot/watchdog-hero.png` (768²), `watchdog-avatar.png` (384²), `watchdog-rest.png` (480²), `watchdog-puzzled.png` (480²), `frontend/public/textures/fabric-wave.jpg` (2400×800). Task 1 copies them in from `C:/Users/DENNIS~1/AppData/Local/Temp/claude/M--Projects-Ascent/e6be705d-cdb6-4915-9ade-8b2b3b1e2eaf/scratchpad/mascot/public/`.
- WCAG AA contrast for every text/surface pair (spec §5.2 table), visible focus rings, `prefers-reduced-motion` respected, keyboard-reachable nav, semantic roles kept.
- Each task ends with `npm run lint`, `npm test` and `npm run build` green in `frontend/`, and `cargo test` green at the repo root (the Rust dashboard tests are unaffected but must stay green).
- Existing tests are updated only as spec §7.1 states; any other test change must be justified in the task report.
- Commit messages end with a `Co-Authored-By:` trailer naming the model that wrote the commit.

---

### Task 1: Assets, fonts, tokens and base styles
Spec: §1 (all), §5.2 (contrast table), §6 delivery, §7 steps 1–2.
- [ ] Copy the five asset files into `frontend/public/` (paths above). Update the font `<link>` in `frontend/index.html` per §1.2.
- [ ] Add `src/styles/tokens.css`, `base.css`, `components.css`, `shell.css`, `screens.css` per §1.3–1.10; import in `main.tsx` in that order with `glass.css` imported last until Task 6 deletes it.
- [ ] Replace `src/styles/glass.test.ts` with `src/styles/tokens.test.ts` (contrast assertions from §5.2 plus the kept assertions listed in §7 step 2).
- [ ] Green: lint, test, build. Commit `feat(ui): watchdog theme tokens, base styles, fonts and mascot assets`.

### Task 2: Data layer and primitives
Spec: §3.0, §4.3, §4.10–4.12, §7 steps 3–4.
- [ ] `src/data/resources.ts` (`useResource`, `__resetResourceCache`; reset in `src/test/setup.ts` `afterEach`), `src/data/search.ts` (`matchFinding`), `src/data/greeting.ts` (time-of-day). Move `App`'s `auditVersion`/`engVersion` to `versions` + `bump`.
- [ ] Primitives: `icons.tsx`, `IconBadge`, `Mascot` (CSS background, aria-hidden, gradient-disc fallback), button classes, `SeverityChip`, `VerdictChip`, `VerdictPill`, `Skeleton`, `EmptyState`, `ErrorState`, `ListCard`, `Toast` (extracted from `Gates.tsx`, with dismiss + pause). Restyle `ErrorBoundary`.
- [ ] Unit tests for `matchFinding`, greeting, `useResource` caching/reset, `Mascot` (no `<img>`, aria-hidden), toast dismiss. Green. Commit `feat(ui): data layer and clay primitives`.

### Task 3: App shell
Spec: §2 (all), §5.1, §7 step 5, §7.1 `Shell.test.tsx` row.
- [ ] Sidebar (avatar disc with mascot, greeting, labelled nav with icons and badges, policy mini-card), top bar (visible h1 "Ascent Console: <screen>", search "Search findings", refresh, bell → gates), skip link, the three responsive modes. `App` passes `title`, `pendingGates`, `policy`, `query`, handlers.
- [ ] Update `Shell.test.tsx` exactly per §7.1; add tests for search Enter → Findings and bell → gates. Green. Commit `feat(ui): watchdog app shell`.

### Task 4: Overview
Spec: §3.1, §4.1, §4.2, §4.4, §4.6, §7 step 6, §7.1 `App.test.tsx` row.
- [ ] `OverviewHero` (mascot, greeting, engagement-free copy per spec, "Define a new scan" CTA → New Scan), KPI row (`KpiTile` with tints), restyled `PolicyGate`, `SeverityBarChart` and `DonutCard` (inline SVG), list cards (top findings, pending approvals via `Gates variant="compact"`, recent audit), report banner with the fabric texture. Remove the `aside` path from `App` and `Shell`.
- [ ] Tests: `App.test.tsx` passes with the §7.1 additions (hero CTA → New scan, bell → gates, KPI tile click → Findings with filter, search Enter → Findings). Green. Commit `feat(ui): watchdog overview`.

### Task 5: Findings and Approval gates
Spec: §3.3, §3.4, §4.5, §4.7, §7 steps 7–8, §7.1 Findings/Gates rows.
- [ ] Findings: KPI filter toggles, table restyle, mobile cards, query + filter plumbing, empty and no-match states (`watchdog-rest`).
- [ ] Approval gates: intro strip, `GateCard` page variant, grid, empty state; compact variant keeps the consent note.
- [ ] Tests per §7.1 (tile filters rows; query filters rows; no-match; compact variant; toast dismiss). Green. Commit `feat(ui): watchdog findings and approval gates`.

### Task 6: New Scan, Report, Audit; remove glass.css
Spec: §3.2, §3.5, §3.6, §4.8, §4.9, §7 step 9, §7.1 NewScan/Report/Audit rows.
- [ ] New Scan two-column layout styling the DAST fields that landed on `main` (select "DAST profile", "Auth header name", "Env var holding its value"); `aria-invalid` on the field named by an error's `field`.
- [ ] Report typography + section index (`#r-…` internal links, h2 text as text). Audit chain card + type filter ("Verdicts / Decisions / Policy / Runs") + timeline.
- [ ] Delete `glass.css` and its import. Tests per §7.1. Green. Commit `feat(ui): watchdog new scan, report and audit`.

### Task 7: Polish
Spec: §5, §7 step 10.
- [ ] Responsive pass at 1440, 1280, 1040, 768, 390; keyboard-only pass; reduced-motion pass; fix any contrast or overflow defects found. Green. Commit `fix(ui): responsive, keyboard and motion polish`.
- (Screenshots and README images are regenerated by the controller afterwards over a privacy-safe demo dataset.)
