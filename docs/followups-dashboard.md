# Ascent dashboard: follow-ups

These come out of the review of `feat/dashboard`. The branch is merge-ready, and none of the items below blocks it.

## Must land before the exploitation stage consumes approvals

1. **Check `gate_hash` before acting.** Every `gate_decision` audit entry records `gate_hash`, which is Crux's `hash_value` of the gate with `status`/`decided_at` removed. Before running anything, the exploitation stage must recompute the hash of the gate it is about to run and refuse to act unless it matches the hash recorded with the approval. This is what prevents a gate edited after approval from running.
2. **Add a cross-process audit lock.** The dashboard's decision lock only works inside its own process. Crux's `AuditLog` also caches `last_hash`, so if `ascent run` triages into the same out dir while a gate is being decided, the chain forks and every later decision fails closed. Add a file lock around all `audit.jsonl` appends, and have Crux re-read the chain tail while holding that lock. Until then, the README warns not to decide gates during a run.
3. **Make gate ids unique per out dir.** A decision recorded in a persistent `audit.jsonl` means any later gate that reuses the same id is treated as already decided.
4. **Re-check scope at execution.** The server refuses to approve gates that aren't in scope, and `ToolRunner` enforces scope on every spawn. The exploitation stage must still go through `ToolRunner` and must not trust the gate's own `in_scope` flag.

## Parked (judged acceptable for now)

- **Missing UI built assets in a moved binary:** the dashboard bakes `CARGO_MANIFEST_DIR/frontend/dist` in at compile time. A relocated or distributed binary must set `ASCENT_DIST`, or `/` returns 404.
- **No React error boundary:** a malformed `queue.json` item blanks the screen.
- **Leftover mockup placeholders in `Shell`:** the "DL" avatar, the search box (no behaviour) and the Settings button (no handler).
- **Unbuilt mockup controls:** the Findings view's segment filters, Filters/Export buttons and row-click detail.
- **Table overflow:** the Findings Mapping column scrolls horizontally at around 1440px wide (`table{min-width:720px}`).
- **Reading and validation hardening:**
  - Reads of the out dir are unbounded.
  - Each audit read is two passes, which can see a different snapshot each time.
  - API payloads get no per-item validation in `getFindings`, `getGates` or `getAudit`.
  - Duplicate ids or hashes produce colliding React keys.
- **Gates screen polish:**
  - There is a single toast slot, so two decisions at once can hide an error toast.
  - The toast's live region is mounted conditionally.
  - There is no retry after a load error.
  - The 409 toast shows a ✓ icon.
- **Report screen:** add `skipHtml` as defence in depth (raw HTML is already escaped to text). A sanitised link renders as `href=""`.
- **Approving an already-decided, out-of-scope gate:** returns 422 rather than 409. Nothing is written either way.
- **Toolchain pinned to Node 20.18:** Vite 6, vitest 3 and jsdom 26. Upgrade to Vite 8 and vitest 4 once Node is at least 20.19; that also clears the dev-only npm advisories.
- **Test gaps:**
  - Gates: two gates decided independently, the toast auto-dismissing, and unmounting mid-request.
  - App: the engagement-fallback tests can't tell the fallback apart from the initial state.
  - Test temp directories are never cleaned up.
