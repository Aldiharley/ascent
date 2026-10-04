# Ascent Dashboard (axum + React, Fluid Glass) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local, premium "Fluid Glass" web dashboard for Ascent: a Rust (axum) backend that serves the pipeline's output (engagement, triaged findings, approval gates, audit log, report) as a JSON API plus the built UI, and a React + TypeScript front-end that renders the four MVP screens in the Fluid Glass style.

**Architecture:** This is subsystem 2, built on top of the pipeline core (subsystem 1). The axum backend reads the pipeline's output directory (`queue.json`, `audit.jsonl`, `report.md`) and the engagement file, exposes a thin read API plus approve/deny endpoints, and serves the compiled React app. The React app is the Fluid Glass UI; its visual design is defined by the mockup at `M:/Projects/Ascent/design/dashboard-mockup.html` (port its token system and glass components). Backend binds to 127.0.0.1 only; the UI shows findings, never sends them anywhere.

**Tech Stack:** Backend: Rust, `axum`, `tokio`, `tower-http` (ServeDir + CORS for dev), `serde`/`serde_json`. Frontend: Vite + React 18 + TypeScript, `vitest` + `@testing-library/react` for tests, plain CSS (the Fluid Glass design system; no CSS framework). Fonts via Google Fonts (Plus Jakarta Sans, JetBrains Mono).

## Global Constraints

- License: Apache-2.0. The dashboard is local-only; the axum server binds `127.0.0.1` and is never exposed.
- Data governance applies to the UI too: it displays findings read from the local output directory and never transmits them anywhere.
- Design source of truth: `M:/Projects/Ascent/design/dashboard-mockup.html`. Reuse its CSS custom-property token system and glass primitives verbatim where possible; do not redesign.
- The backend reads the same artifacts the pipeline writes: `queue.json` (triaged items), `audit.jsonl` (hash-chained log), `report.md`, and the engagement YAML. No database.
- Approve/deny on a gate appends a decision entry to `audit.jsonl`; it never itself runs an exploit (the exploitation stage, a later plan, is what acts on an approval).
- Backend: `cargo clippy` clean. Frontend: `tsc --noEmit` clean, `vitest` green. Every task ends green and committed.

## Assets (generate with the Higgsfield CLI if needed)

The core UI needs **no image assets**, the Fluid Glass look is pure CSS (gradients, `backdrop-filter`, SVG icons). Only generate assets if a task below calls for one or you want polish. When you do, use the **Higgsfield CLI** (`@higgsfield/cli`; models `nano_banana_pro` [Pro plan], `flux_kontext`, `nano_banana_flash`; `bytedance_image_upscale` with `resolution 2k|4k` and `remove_bg`). Candidates and only-if-wanted:
- **App favicon / logo mark** (the "A" shield) as a crisp PNG/SVG, if the CSS mark is not enough.
- **Empty-state illustration** for "no engagement loaded" / "no findings yet".
- **Login or splash art** if an auth screen is added later.
- **OG/share image** if the dashboard is ever shared.
Keep generated assets in `frontend/src/assets/`, embed small ones as data URIs, and record the prompt + model used in `design/ASSETS.md`.

---

### Task 1: Backend scaffold — axum server + static serving

**Files:**
- Create: `src/bin/dashboard.rs`, `frontend/dist/.gitkeep`
- Modify: `Cargo.toml` (add deps + `[[bin]]`)

**Interfaces:**
- Produces: a `dashboard` binary; `GET /api/health` returns `{"ok":true}`; `/` and other non-`/api` paths serve `frontend/dist` (the built UI). A `State { out_dir: String, engagement: String }` passed to handlers.

- [ ] **Step 1: Add deps and bin to `Cargo.toml`**
```toml
[[bin]]
name = "dashboard"
path = "src/bin/dashboard.rs"

[dependencies]
# ...existing...
axum = "0.7"
tokio = { version = "1", features = ["rt-multi-thread","macros","net"] }
tower-http = { version = "0.6", features = ["fs","cors"] }
```
- [ ] **Step 2: Write the failing test** (in `src/bin/dashboard.rs`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn health_ok() {
        let app = router(AppState{ out_dir: "out".into(), engagement: "e.yaml".into() });
        let resp = app.oneshot(axum::http::Request::builder().uri("/api/health").body(axum::body::Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), 200);
    }
}
```
- [ ] **Step 3: Run, verify fail** — `cargo test --bin dashboard` → FAIL.
- [ ] **Step 4: Implement `src/bin/dashboard.rs`**
```rust
use axum::{Router, routing::get, Json, extract::State};
use tower_http::services::ServeDir;
use tower_http::cors::CorsLayer;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState { pub out_dir: String, pub engagement: String }

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(|| async { Json(serde_json::json!({"ok":true})) }))
        .fallback_service(ServeDir::new("frontend/dist"))
        .layer(CorsLayer::permissive())   // dev only; local bind
        .with_state(Arc::new(state))
}

#[tokio::main]
async fn main() {
    let state = AppState { out_dir: std::env::var("ASCENT_OUT").unwrap_or("out".into()),
                           engagement: std::env::var("ASCENT_ENG").unwrap_or("samples/engagement.example.yaml".into()) };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8787").await.unwrap();
    println!("ascent dashboard on http://127.0.0.1:8787");
    axum::serve(listener, app).await.unwrap();
}
```
Add `use tower::util::ServiceExt;` in the test module for `oneshot` (add `tower` to dev-deps if needed). Create `frontend/dist/.gitkeep`.
- [ ] **Step 5: Run tests** → PASS; `cargo clippy` clean.
- [ ] **Step 6: Commit**
```bash
git add Cargo.toml src/bin/dashboard.rs frontend/dist/.gitkeep
git commit -m "feat(dashboard): axum server scaffold + static serving"
```

---

### Task 2: Output readers (engagement, findings, audit, report)

**Files:**
- Create: `src/dashboard/mod.rs`, `src/dashboard/read.rs`
- Modify: `src/bin/dashboard.rs` (`#[path="../dashboard/mod.rs"] mod dashboard;` or restructure as a lib module)

**Interfaces:**
- Produces (pure functions, testable without a server):
  - `read_findings(out_dir: &str) -> Vec<serde_json::Value>` — parses `queue.json` (the triaged items). Returns `[]` if missing.
  - `read_audit(out_dir: &str) -> (Vec<serde_json::Value>, bool)` — parses `audit.jsonl` into entries and returns `(entries, chain_ok)` by re-walking the hash chain (prev_hash links + entry_hash recompute mirrors Crux's `verify`).
  - `read_report(out_dir: &str) -> String` — reads `report.md` (or "" if missing).
  - `read_engagement(path: &str) -> serde_json::Value` — the scope info as JSON.

- [ ] **Step 1: Write the failing test**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn reads_findings(/* tmp */) {
        let dir = std::env::temp_dir().join("ascent_read_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("queue.json"),
            r#"[{"verdict":"TRUE_POSITIVE","confidence":0.9,"finding":{"title":"SQLi"}}]"#).unwrap();
        let f = read_findings(dir.to_str().unwrap());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0]["verdict"], "TRUE_POSITIVE");
    }
}
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement `src/dashboard/read.rs`** — `std::fs::read_to_string` + `serde_json`; for `read_audit`, parse each JSONL line, then verify the chain by recomputing each entry's hash over its body (sorted keys, matching Crux's `_hash`) and checking `prev_hash` continuity; return `chain_ok`.
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit**
```bash
git add src/dashboard/ src/bin/dashboard.rs
git commit -m "feat(dashboard): output readers for findings/audit/report/engagement"
```

---

### Task 3: API routes (read + gate approve/deny)

**Files:**
- Modify: `src/bin/dashboard.rs` (add routes), `src/dashboard/read.rs` (gate read + append-decision)

**Interfaces:**
- Produces routes on `router`:
  - `GET /api/engagement` → engagement JSON.
  - `GET /api/findings` → `read_findings`.
  - `GET /api/audit` → `{entries, chain_ok}`.
  - `GET /api/report` → `{markdown}`.
  - `GET /api/gates` → pending approval actions from `gates.json` (list of `{id,title,why,command,target,in_scope}`); `[]` if missing.
  - `POST /api/gates/:id/:decision` (`approve`|`deny`) → appends a decision entry to `audit.jsonl`, marks the gate resolved in `gates.json`, returns `{ok:true}`. (It does NOT run any exploit; the later exploitation stage consumes approvals.)
- Produces `samples/gates.example.json` with one example gate so the UI has content.

- [ ] **Step 1: Write the failing test**
```rust
#[tokio::test]
async fn findings_route_returns_json() {
    // arrange a temp out_dir with queue.json, build router with that state, GET /api/findings, assert 200 + body
}
#[tokio::test]
async fn approve_appends_audit() {
    // arrange gates.json with id "g1"; POST /api/gates/g1/approve; assert 200 and that audit.jsonl grew by one decision entry
}
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement the handlers** — each reads via Task 2 functions keyed off `State.out_dir`/`engagement`; the POST validates `decision in {approve,deny}`, appends an audit entry `{ts,type:"gate_decision",gate_id,decision}` (hash-chained onto the existing log), updates `gates.json`.
- [ ] **Step 4: Run tests** → PASS; clippy clean.
- [ ] **Step 5: Commit**
```bash
git add src/bin/dashboard.rs src/dashboard/read.rs samples/gates.example.json
git commit -m "feat(dashboard): read API + gate approve/deny endpoints"
```

---

### Task 4: Frontend scaffold + Fluid Glass design system

**Files:**
- Create: `frontend/` (Vite React-TS), `frontend/src/styles/glass.css` (the design system), `frontend/src/App.tsx`, `frontend/src/components/Shell.tsx`, `frontend/src/components/Shell.test.tsx`

**Interfaces:**
- Produces: a Vite React+TS app; `glass.css` carrying the `:root` token system and `.glass` primitive **ported from `design/dashboard-mockup.html`** (field/blob background, glass panel, radius, shadows, fonts); `<Shell>` rendering the icon rail + topbar + a content slot.

- [ ] **Step 1: Create the app**
Run: `npm create vite@latest frontend -- --template react-ts && cd frontend && npm i && npm i -D vitest @testing-library/react @testing-library/jest-dom jsdom`. Configure `vitest` (jsdom env) in `vite.config.ts`.
- [ ] **Step 2: Write the failing component test**
```tsx
// frontend/src/components/Shell.test.tsx
import { render, screen } from "@testing-library/react";
import { Shell } from "./Shell";
test("renders brand and nav", () => {
  render(<Shell><div>content</div></Shell>);
  expect(screen.getByText("content")).toBeInTheDocument();
  expect(screen.getByLabelText("Findings")).toBeInTheDocument();
});
```
- [ ] **Step 3: Run, verify fail** — `npm run test` → FAIL.
- [ ] **Step 4: Port `glass.css` and implement `Shell.tsx`** — copy the token `:root`, `body` background (field + blobs), and `.glass` rules from the mockup into `glass.css`; `Shell` renders the rail (nav buttons with `aria-label`s: Overview, Findings, Approval gates, Report, Audit), the topbar (search, engagement status, avatar), and `{children}`. Import `glass.css` in `main.tsx`; add the Google Fonts `<link>` in `index.html`.
- [ ] **Step 5: Run tests + typecheck** → `npm run test` PASS, `npx tsc --noEmit` clean.
- [ ] **Step 6: Commit**
```bash
git add frontend && git commit -m "feat(dashboard): react scaffold + Fluid Glass design system + shell"
```

---

### Task 5: Findings screen (KPIs + table)

**Files:**
- Create: `frontend/src/api.ts`, `frontend/src/screens/Findings.tsx`, `frontend/src/screens/Findings.test.tsx`, `frontend/src/components/{Kpi,VerdictChip,SeverityStripe,ConfidenceBar}.tsx`

**Interfaces:**
- Consumes: `GET /api/findings`.
- Produces: `api.ts` with typed `getFindings(): Promise<TriageItem[]>` (type mirrors the queue JSON: `{finding:{title,rule_id,severity,url,cwe,...}, verdict, confidence, fp_likelihood, rationale, remediation}`); `<Findings>` rendering the KPI row (counts by verdict + rings) and the glass table (severity stripe, confidence bar, verdict chip, locus, CWE/WSTG tags) exactly as the mockup lays it out.

- [ ] **Step 1: Write the failing test** (mock fetch)
```tsx
import { render, screen } from "@testing-library/react";
import { Findings } from "./Findings";
test("renders a finding row and KPI", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify([
    {finding:{title:"SQL injection",rule_id:"sqli",severity:"CRITICAL",url:"/login",cwe:"CWE-89"},
     verdict:"TRUE_POSITIVE",confidence:0.95,fp_likelihood:0.05,rationale:"r",remediation:"fix"}])));
  render(<Findings/>);
  expect(await screen.findByText("SQL injection")).toBeInTheDocument();
  expect(screen.getByText(/True positive/i)).toBeInTheDocument();
});
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement** the components and screen, styling via the ported glass tokens (reuse the mockup's classes: `.kpi`, `.ring`, `.panel`, `.verdict`, `.sev`, `.conf .bar`, `.stripe`, `.tag`). Compute KPI counts from the findings array.
- [ ] **Step 4: Run tests + typecheck** → PASS/clean.
- [ ] **Step 5: Commit**
```bash
git add frontend/src && git commit -m "feat(dashboard): findings screen (KPIs + glass table)"
```

---

### Task 6: Approval-gate panel (the human-in-the-loop screen)

**Files:**
- Create: `frontend/src/screens/Gates.tsx`, `frontend/src/screens/Gates.test.tsx`
- Modify: `frontend/src/api.ts` (`getGates`, `decideGate`)

**Interfaces:**
- Consumes: `GET /api/gates`, `POST /api/gates/:id/:decision`.
- Produces: `<Gates>` listing pending gates as glass cards (title, rationale, the proposed command in a mono block, an in-scope badge, Approve/Deny buttons). Approve/Deny call `decideGate(id, decision)` and remove the card; a toast confirms. Shows an empty state ("No actions awaiting approval") when none.

- [ ] **Step 1: Write the failing test**
```tsx
test("approving a gate calls the api and removes it", async () => {
  vi.spyOn(globalThis,"fetch")
    .mockResolvedValueOnce(new Response(JSON.stringify([{id:"g1",title:"Confirm SSRF",why:"w",command:"nuclei ...",target:"/x",in_scope:true}])))
    .mockResolvedValueOnce(new Response(JSON.stringify({ok:true})));
  render(<Gates/>);
  const btn = await screen.findByRole("button",{name:/approve/i});
  btn.click();
  expect(await screen.findByText(/No actions awaiting approval/i)).toBeInTheDocument();
});
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement** `<Gates>` + the two api functions; reuse the mockup's `.gate`, `.gcard`, `.cmd`, `.scope-ok`, `.approve`, `.deny` styles.
- [ ] **Step 4: Run tests + typecheck** → PASS/clean.
- [ ] **Step 5: Commit**
```bash
git add frontend/src && git commit -m "feat(dashboard): approval-gate panel with approve/deny"
```

---

### Task 7: Report + Audit screens

**Files:**
- Create: `frontend/src/screens/Report.tsx`, `frontend/src/screens/Audit.tsx`, `frontend/src/screens/Audit.test.tsx`
- Modify: `frontend/src/api.ts` (`getReport`, `getAudit`)

**Interfaces:**
- Consumes: `GET /api/report`, `GET /api/audit`.
- Produces: `<Report>` renders the markdown (use a tiny safe renderer or `marked` from cdn-pinned UMD; sanitise) inside a glass panel. `<Audit>` renders the hash-chained entries as a glass feed with a chain-OK/FAIL badge from `chain_ok`.

- [ ] **Step 1: Write the failing test** (Audit)
```tsx
test("audit shows chain status", async () => {
  vi.spyOn(globalThis,"fetch").mockResolvedValue(new Response(JSON.stringify(
    {entries:[{ts:"t",verdict:"TRUE_POSITIVE",finding_id:"n1"}], chain_ok:true})));
  render(<Audit/>);
  expect(await screen.findByText(/chain .*OK/i)).toBeInTheDocument();
});
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement** both screens; `<Audit>` uses the mockup's `.audit`/`.feed`/`.ev` styles; `<Report>` shows the markdown in a `.glass .panel`.
- [ ] **Step 4: Run tests + typecheck** → PASS/clean.
- [ ] **Step 5: Commit**
```bash
git add frontend/src && git commit -m "feat(dashboard): report + audit screens"
```

---

### Task 8: Navigation wire-up, build, and end-to-end local run

**Files:**
- Modify: `frontend/src/App.tsx` (tab state → render Findings/Gates/Report/Audit; wire the rail buttons), `frontend/package.json` (build script), `README.md` (run instructions)

**Interfaces:**
- Produces: `<App>` holds the active-screen state, the rail switches screens, each screen fetches its own data. `npm run build` outputs to `frontend/dist`; the axum `dashboard` binary serves it.

- [ ] **Step 1: Write the failing test** (App switches screens)
```tsx
test("rail switches to gates", async () => {
  // mock fetch for findings (initial) and gates; click the "Approval gates" rail button; assert a gates-screen marker appears
});
```
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement** `<App>` tab state + rail wiring; ensure each screen renders inside `<Shell>`.
- [ ] **Step 4: Run tests + typecheck** → PASS/clean.
- [ ] **Step 5: Real end-to-end run** — run the pipeline (subsystem 1) against a lab target to produce `out/queue.json`, `out/audit.jsonl`, `out/report.md`; copy `samples/gates.example.json` to `out/gates.json`; `cd frontend && npm run build`; from the repo root `ASCENT_OUT=out cargo run --bin dashboard`; open `http://127.0.0.1:8787` and confirm the Fluid Glass dashboard shows the findings, the gate card approves (and appends to the audit log), and the audit tab shows chain OK.
- [ ] **Step 6: Commit**
```bash
git add frontend README.md && git commit -m "feat(dashboard): navigation, build, end-to-end local run"
```

---

## Self-review notes (coverage)

- PRD section 8b screens: scope (topbar, Task 4) + findings queue (Task 5) + approval gates (Task 6) + report & audit (Task 7), with navigation (Task 8). Backend: scaffold (1), readers (2), API incl. approve/deny (3).
- Design: the Fluid Glass system is ported from `design/dashboard-mockup.html` (Task 4) and reused across screens; no redesign.
- Safety/governance: local bind only; UI reads findings and never transmits them; approve/deny only records a decision to the audit log and never runs an exploit (the exploitation stage, a later plan, consumes approvals).
- Assets: the UI needs none; the Higgsfield-CLI section lists optional extras and where to record prompts.
- Depends on subsystem 1 (the pipeline core) having produced an `out/` directory; the end-to-end run in Task 8 uses it. Gates are driven by `gates.json` (example provided) until the exploitation stage populates them.
- Verify in Task 2 that the audit hash recomputation matches Crux's `audit.py` `_hash` (sorted keys, compact separators) so `chain_ok` agrees with Crux's own `verify`.
