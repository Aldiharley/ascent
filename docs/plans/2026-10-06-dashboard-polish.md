# Dashboard polish implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use subagent-driven-development (recommended) or executing-plans to implement this plan task by task.

**Goal:** close the frontend follow-ups parked in `docs/followups-dashboard.md`. After this plan:
- one malformed item from the backend can't blank the dashboard;
- the topbar shows only things that work;
- the approval-gate screen handles concurrent decisions, failures and screen readers properly.

**Scope:** frontend only (`frontend/src`), no backend changes.

**Tech:** React 18.3, TypeScript, vitest 3 (jsdom, globals, jest-dom), plain CSS in `src/styles/glass.css` (a verbatim port of the mockup; append to it, don't restyle it).

## Global constraints

- All existing tests keep passing (48). `npx tsc -b` is clean, `npm run build` works, and `frontend/dist` stays untracked.
- Data that came from scanned targets renders only as React text. Never use `dangerouslySetInnerHTML`, and never put it in `href` or `src`.
- No `<h1>` for visible headings, because `glass.css` hides `h1`. A visually-hidden `h1` for screen readers is fine.
- Strict TDD: write the test, watch it fail, implement, watch it pass.

---

### Task 1: Payload validation and an error boundary

**Files:** modify `src/api.ts` and `src/App.tsx`. Create `src/components/ErrorBoundary.tsx` and `src/components/ErrorBoundary.test.tsx`. Extend `src/api` tests if they exist; otherwise create `src/api.test.ts`.

**Requirements:**
- `getFindings()` keeps only items that are non-null objects with a non-null object `finding`. Everything else is dropped, so one bad row can't crash rendering.
- `getGates()` keeps only non-null objects with a non-empty string `id`, and drops duplicate ids (the first one wins).
- `getAudit()` keeps only `entries` that are non-null objects.
- `<ErrorBoundary>` is a class component. When a child throws during render, it shows a glass panel with `role="alert"` reading "This view failed to render." It also offers a **Try again** button that resets the boundary, so the children re-mount.
- In `App.tsx`, each screen is wrapped in its own `<ErrorBoundary>`. On Overview, the findings main column and each aside panel get separate boundaries, so a failure in one leaves the others working.

**Tests:**
- `getFindings` drops `null`, a non-object, and an item whose `finding` is `null`, and keeps the valid ones.
- `getGates` drops items without an `id` and duplicate ids.
- `getAudit` drops `null` entries.
- `ErrorBoundary` shows the alert when a child throws, and Try again re-renders the child (use a child that throws only on its first render).
- An `App` test: if the gates panel throws, the findings table on Overview still renders.

**Commit:** `fix(frontend): validate API payloads and isolate screens with error boundaries`

---

### Task 2: Shell cleanup

**Files:** modify `src/components/Shell.tsx` and `src/components/Shell.test.tsx`. Append to `src/styles/glass.css` if needed.

**Requirements:**
- Remove the placeholder controls that do nothing:
  - the hard-coded "DL" avatar;
  - the search input, which has no behaviour;
  - the Settings rail button, which has no handler.
- Keep the rail's five working buttons (Overview, Findings, Approval gates, Report, Audit) and the engagement status pill.
- The status pill's dot is neutral (grey, a `.dot.idle` class) when there is no engagement, i.e. when the status is the default "no engagement loaded". It is green only when an engagement is loaded.
- Add a visually hidden `<h1>` reading "Ascent Console" using a `.sr-only` utility class, appended to `glass.css`. Scope it so it doesn't depend on the mockup's `h1{font-size:0}` rule.
- Give the topbar layout a single tidy row now that the search box is gone. Adjust the mockup's grid only as much as needed.

**Tests:**
- There is no element with the accessible name "Search" or "Settings", and no "DL" text.
- The five rail buttons are still present.
- The dot has class `idle` with the default status, and doesn't when `status="engagement: x"`.
- A heading with the name "Ascent Console" exists.

**Commit:** `fix(frontend): remove inert placeholders from the shell; neutral status when idle`

---

### Task 3: Gates screen polish

**Files:** modify `src/screens/Gates.tsx` and `src/screens/Gates.test.tsx`. Append to `src/styles/glass.css` if needed.

**Requirements:**
- **A toast stack instead of a single slot.** Every decision outcome adds its own toast, each auto-dismissing after 5 s on its own timer. A later success must not hide an earlier error. Cap the stack at 4 (drop the oldest). All timers are cleared on unmount.
- **Persistent live regions.** Render two always-mounted containers: `aria-live="polite"` for successes and `aria-live="assertive"` (`role="alert"`) for errors. Toasts render inside them, so screen readers announce them reliably.
- **409 ("already decided") uses a neutral info icon** (for example "i"), not the ✓.
- **Retry on load error.** The error state shows a **Retry** button that re-fetches the gates.
- **Ref-based double-submit guard.** Track in-flight ids in a `useRef<Set<string>>` as well as state, and check the ref at the start of `decide`, so a second click before re-render can't send a second POST.

**Tests:**
- Two gates: approving g1 leaves g2's buttons enabled and its card present.
- Toast auto-dismiss: with fake timers the toast is visible, and after 5 s it's gone.
- An error toast stays visible after a later success toast.
- Unmount mid-request: resolve the decision after unmount; no React warning and no throw.
- Retry: the first load fails, then clicking Retry loads the gates.
- 409 shows the info icon, not ✓.
- Two synchronous clicks on Approve send exactly one POST.

**Commit:** `fix(frontend): gate screen toast stack, live regions, retry and double-submit guard`

---

## Coverage

These tasks close the parked dashboard items for the error boundary, the mockup placeholders, the Gates screen polish (toast slot, live region, retry, 409 icon, stale-closure guard, test gaps), the green dot on the empty state, and the missing page h1. Out of scope, still parked: anything listed under the backend or pre-exploitation requirements.
