# Gated Verification (Phase 5 MVP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Crux's triaged findings into human-gated, detect-only confirmation actions: the pipeline *proposes* an inert verification command per high-confidence finding; a human *approves* it in the dashboard; an *executor* then runs only approved, allow-listed, scope-checked probes and records the confirmation to the hash-chained audit log. Nothing touches a target without a human approval.

**Architecture:** This is PRD Phase 5's MVP (see `docs/superpowers/specs/2026-10-06-gated-exploitation-design.md`), the "verification" layer: detect-only only, no weaponisation. A deterministic **proposer** maps findings to proposed gates (reusing the dashboard's existing gate shape + approval flow). An **executor** runs approved gates through the existing scope-checked `ToolRunner`, binding each run to the `gate_hash` the approval recorded. The tamper-evident gate/audit primitives, currently in the dashboard binary, are shared so there is ONE implementation.

**Tech Stack:** Rust (stable), serde_json, the existing `ScopeGuard`/`Runner`/`ToolRunner`/`TriageItem`, and `crux::canon::hash_value` + `crux::AuditLog`. No new crates. No external LLM. Reuses nuclei (already required) as the only detect-only probe tool in this MVP.

## Global Constraints

- **Nothing runs against a target without a recorded human approval.** The executor runs a gate ONLY when the audit log has an `approved` `gate_decision` for it whose recorded `gate_hash` equals the recomputed hash of the current gate (an edit after approval is refused).
- **Detect-only, allow-listed.** The executor runs only commands the proposer emits: nuclei re-checks of the form `nuclei -id <template-id> -u <url> -silent -jsonl` (detection templates, never intrusive/exploit flags). The executor validates the structured `argv` against this allow-list and refuses anything else.
- **Scope at the execution boundary.** Every executor run goes through `ToolRunner`, which re-checks the target host against the engagement scope independently of the gate's own `in_scope` flag.
- **Commands are structured `argv`, never shell strings.** The executor spawns `argv` directly (no shell), so there is no command-string parsing or injection surface. A human-readable `command` string is stored only for display.
- **Audited.** Each execution appends a Crux-compatible, hash-chained `gate_execution` entry (gate_id, gate_hash, outcome) via the shared append helper; the chain stays verifiable.
- **Hard exclusions (PRD §10), NOT built:** autonomous firing, C2/implants, lateral movement, persistence, exfiltration, autonomous privesc, and any exploit-tier (weaponising) tool. This MVP confirms findings; it does not exploit.
- Rust stable; `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt` applied; every task ends green and committed. Commit trailer: a blank line then `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Prerequisite satisfied here: `docs/followups-dashboard.md` item 1 ("check `gate_hash` before acting") is implemented by the executor. The cross-process audit-lock follow-up still applies: run `ascent verify` only when no `ascent run` is writing the same out dir (the executor fails closed on a broken chain).

---

### Task 1: Share the gate + audit primitives

**Files:**
- Create: `src/gatesio.rs` (the shared primitives), `tests` inline.
- Modify: `src/dashboard/gates.rs` (re-export/use the shared ones instead of its own copies), `src/bin/dashboard.rs` (include the shared module), `src/main.rs` (`mod gatesio;`).

**Interfaces:**
- Produces (pure, both binaries use them):
  - `pub fn gate_hash(gate: &serde_json::Value) -> String` — canonical hash of the gate minus `status`/`decided_at` (moved verbatim from `dashboard/gates.rs`).
  - `pub fn read_pending_gates(out_dir: &str) -> Vec<serde_json::Value>` (moved).
  - `pub fn approved_decisions(out_dir: &str) -> Vec<(String, String)>` — for each `gate_decision` with `decision=="approved"`, `(gate_id, recorded_gate_hash)` read from the audit log. (The audit `gate_decision` entries already carry the gate hash; this reads it back.)
  - `pub fn append_chained(audit_path: &str, mut body: serde_json::Map<String, serde_json::Value>) -> Result<(), Box<dyn std::error::Error>>` — append one hash-chained JSON line: set `prev_hash` to the last entry's `entry_hash` (or GENESIS), compute `entry_hash = crux::canon::hash_value(body)`, write. (Generalises `append_decision`; `gate_decision` and the new `gate_execution` both use it.)

- [ ] **Step 1: Write the failing test** (`src/gatesio.rs` tests): `gate_hash` ignores `status`/`decided_at`; `append_chained` writes a line that `crux::AuditLog::verify()` accepts and whose `prev_hash` links to the prior entry; `approved_decisions` returns only approved ids with their recorded hash.
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn tmp() -> std::path::PathBuf { /* unique temp dir */ std::env::temp_dir().join(format!("ascent_gio_{}_{}", std::process::id(), line!())) }

    #[test]
    fn gate_hash_ignores_resolution_fields() {
        let a = json!({"id":"g1","command":"nuclei -id x -u http://h/","target":"http://h/"});
        let mut b = a.clone();
        b["status"] = json!("approved"); b["decided_at"] = json!("t");
        assert_eq!(gate_hash(&a), gate_hash(&b));
    }

    #[test]
    fn append_chained_is_crux_verifiable() {
        let d = tmp(); std::fs::create_dir_all(&d).unwrap();
        let ap = d.join("audit.jsonl"); let aps = ap.to_str().unwrap();
        let mut body = serde_json::Map::new();
        body.insert("type".into(), json!("gate_execution"));
        body.insert("gate_id".into(), json!("g1"));
        append_chained(aps, body).unwrap();
        let (ok, _) = crux::AuditLog::new(&ap).verify();
        assert!(ok);
    }
}
```
- [ ] **Step 2: Run, verify fail** — `cargo test gatesio` → FAIL.
- [ ] **Step 3: Implement** — move `gate_hash` and `read_pending_gates` from `dashboard/gates.rs` into `src/gatesio.rs` verbatim; add `approved_decisions` (adapt `recorded_decisions` to also return the recorded hash — read the `gate_hash`/`finding_hash` field the decision entry stores) and `append_chained` (generalise `append_decision`'s prev-hash + entry-hash logic, reading GENESIS from `crux::audit::GENESIS`). In `dashboard/gates.rs`, `#[path = "../gatesio.rs"] mod gatesio;` is NOT needed there because the dashboard bin will include it once; instead have `dashboard/gates.rs` call `crate`-level `gatesio` — simplest: the dashboard bin adds `#[path="../gatesio.rs"] mod gatesio;` and `dashboard/gates.rs` uses `super`/`crate` paths. Keep `decide_gate` and the HTTP-coupled parts in `dashboard/gates.rs`, delegating the hash/append/read to `gatesio`. `src/main.rs` gets `mod gatesio;`.
- [ ] **Step 4: Run tests** → all pass, including the 62 dashboard tests (the refactor is behaviour-preserving). clippy clean; fmt.
- [ ] **Step 5: Commit** — `refactor: share gate_hash/audit primitives between the pipeline and dashboard`.

---

### Task 2: Proposed-action model + allow-list

**Files:** Create `src/exploit/mod.rs` (`pub mod propose; pub mod execute;` — execute added in Task 4), `src/exploit/propose.rs` (model + allow-list here). Modify `src/main.rs` (`mod exploit;`).

**Interfaces:**
- Produces:
  - A proposed gate is a `serde_json::Value` object with: `id`, `finding_id`, `title`, `why`, `command` (display string), `tool` (`"nuclei"`), `args` (Vec<String>, the argv after the tool), `target` (the URL), `in_scope` (bool), `detect_only` (`true`), `expected_evidence`, `why_it_might_fail`. (Superset of the dashboard's existing `{id,title,why,command,target,in_scope}`, so the dashboard still reads it.)
  - `pub fn is_allowed_detect_only(tool: &str, args: &[String]) -> bool` — true ONLY for `tool=="nuclei"` with args of the shape `-id <id> -u <url> -silent -jsonl` (an `-id`, a `-u`, and only detection flags; reject any arg in a deny-set of intrusive/exploit flags, e.g. anything containing `fuzz`, `-as`, `-code`, `-headless`, `interactsh` is out for the MVP, and reject `-u` whose value isn't an http(s) URL).

- [ ] **Step 1: Write the failing test** — `is_allowed_detect_only("nuclei", &["-id","CVE-x","-u","http://h/","-silent","-jsonl"].map(Into))` is true; a non-nuclei tool is false; args without `-id`/`-u` false; args containing an intrusive flag false; `-u ftp://..` false.
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement** `is_allowed_detect_only` (strict allow-list, deny-set, URL check with the `url` crate) in `src/exploit/propose.rs`; create `src/exploit/mod.rs` with `pub mod propose;` and `mod exploit;` in main.rs.
- [ ] **Step 4: Run tests** → pass; clippy/fmt.
- [ ] **Step 5: Commit** — `feat(verify): proposed-action model and detect-only allow-list`.

---

### Task 3: The proposer

**Files:** Modify `src/exploit/propose.rs`.

**Interfaces:**
- Consumes: `TriageItem` (from `queue.json`), `ScopeGuard`.
- Produces: `pub fn propose(items: &[TriageItem], guard: &ScopeGuard, min_confidence: f64) -> Vec<serde_json::Value>` — for each item whose verdict is `TRUE_POSITIVE` and `confidence >= min_confidence` and whose finding is a nuclei DAST finding with a non-empty `url` and `rule_id`, emit ONE proposed gate: a detect-only nuclei re-check `nuclei -id <rule_id> -u <url> -silent -jsonl`, `in_scope = guard.in_scope(url)`, `detect_only=true`, `expected_evidence="nuclei re-reports template <rule_id> at <url>"`, `why_it_might_fail="the original match was transient, rate-limited, or already remediated"`, `id="verify:<rule_id>:<url>"`. Non-nuclei or url-less findings are skipped (this MVP only re-checks nuclei DAST findings). The emitted `args` MUST satisfy `is_allowed_detect_only`.
- `pub fn write_proposed(out_dir: &str, gates: &[serde_json::Value]) -> Result<(), Box<dyn std::error::Error>>` — merge the proposed gates into `<out_dir>/gates.json` (append; don't drop existing/already-resolved gates; de-dupe by `id`), atomic temp+rename.

- [ ] **Step 1: Write the failing test** — a `TRUE_POSITIVE` nuclei item (confidence 0.9, url, rule_id) → one proposed gate with `tool=="nuclei"`, args passing `is_allowed_detect_only`, `in_scope` reflecting the guard; an `ABSTAIN` or low-confidence item → none; a finding with empty url → none; `write_proposed` writes a gates.json the dashboard's `read_pending_gates` returns.
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement** `propose` + `write_proposed`.
- [ ] **Step 4: Run tests** → pass; clippy/fmt.
- [ ] **Step 5: Commit** — `feat(verify): deterministic proposer (findings -> detect-only gates)`.

---

### Task 4: The executor

**Files:** Create `src/exploit/execute.rs`; modify `src/exploit/mod.rs` (`pub mod execute;`).

**Interfaces:**
- Consumes: `gatesio::{approved_decisions, gate_hash, read-gates}`, `is_allowed_detect_only`, `Runner`, `ScopeGuard`.
- Produces:
  - `#[derive(Debug, PartialEq)] pub struct VerificationResult { pub gate_id: String, pub outcome: Outcome }` where `enum Outcome { Confirmed, NotConfirmed, Refused(String) }`.
  - `pub fn verify_approved(out_dir: &str, guard: &ScopeGuard, runner: &dyn Runner) -> Result<Vec<VerificationResult>, Box<dyn std::error::Error>>` — for each gate in `gates.json` whose id has an `approved` decision in the audit log:
    1. recompute `gate_hash(gate)`; if it ≠ the recorded hash → `Refused("gate changed after approval")`, run nothing, audit the refusal;
    2. require `gate["detect_only"]==true`, `is_allowed_detect_only(tool,args)`, and `guard.in_scope(target)` → else `Refused(reason)`, run nothing;
    3. run `runner.run_json(tool, args, &[host_of(target)])` (ToolRunner re-checks scope before spawning); `Confirmed` if it returns ≥1 row, else `NotConfirmed`;
    4. append a `gate_execution` audit entry via `gatesio::append_chained` binding `gate_id`, `gate_hash`, and the outcome string. Never append on a refusal-before-run except the refusal record.
  - It NEVER runs a gate that is pending or denied; one gate at a time.

- [ ] **Step 1: Write the failing tests** — using a fake `Runner` and a temp out dir with a gates.json + an audit.jsonl containing an `approved` `gate_decision` (hash-matching) for a detect-only nuclei gate: `verify_approved` → `Confirmed` when the fake returns a row, `NotConfirmed` when it returns none, and a new `gate_execution` entry appears and `crux::AuditLog::verify()` still passes. A gate whose stored hash ≠ recorded → `Refused`, runner NOT called. A gate not approved → skipped. A non-allow-listed/argv-tampered gate → `Refused`, runner not called.
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement** `verify_approved` + `host_of` (reuse scope's URL-host logic or `url` crate). Enforce the order: hash check → allow-list/scope check → run → audit.
- [ ] **Step 4: Run tests** → pass; clippy/fmt.
- [ ] **Step 5: Commit** — `feat(verify): executor runs only approved, hash-bound, allow-listed detect-only probes`.

---

### Task 5: CLI wiring (`ascent run --propose`, `ascent verify`)

**Files:** Modify `src/main.rs`.

**Interfaces:**
- Produces:
  - `ascent run` gains `--propose` (and `--min-confidence <f64>`, default 0.8): after triage, call `propose(items, &guard, min_confidence)` and `write_proposed(out_dir, …)` so the run leaves proposed gates for the dashboard. Without `--propose`, behaviour is unchanged.
  - A new subcommand `ascent verify --engagement <f> --out <dir>`: load the engagement, build `ScopeGuard` + `ToolRunner` (NOT dry-run), call `verify_approved`, print a summary (`confirmed=… not_confirmed=… refused=…`) and the audit path. This is the human-triggered execution step.

- [ ] **Step 1: Write the parse tests** — `ascent run --engagement e --propose --min-confidence 0.9` parses; `ascent verify --engagement e --out out` parses.
- [ ] **Step 2: Run, verify fail** → FAIL.
- [ ] **Step 3: Implement** — add the flag + subcommand; `run` needs the triaged `items` to propose from (the pipeline currently returns a `Summary`; either have `run_pipeline` optionally return the items, or re-read `<out_dir>/queue.json` after the run and propose from that — prefer re-reading `queue.json` to avoid changing `run_pipeline`'s signature). `verify` wires `verify_approved`.
- [ ] **Step 4: Run tests** → `cargo test` pass; clippy `--all-targets -- -D warnings` clean; fmt.
- [ ] **Step 5: Commit** — `feat(verify): ascent run --propose and ascent verify subcommand`.

---

### Task 6: Dashboard surfaces the proposal detail

**Files:** Modify `frontend/src/screens/Gates.tsx`, `frontend/src/api.ts` (extend the `Gate` type), `frontend/src/screens/Gates.test.tsx`.

**Interfaces:**
- The `Gate` type gains optional `detect_only?: boolean`, `expected_evidence?: string`, `why_it_might_fail?: string`. The gate card shows a "DETECT-ONLY" badge when `detect_only`, plus "Expected evidence" and "Why it might fail" lines when present. All rendered as React text (no HTML sink). No behaviour change to approve/deny.

- [ ] **Step 1: Write the failing test** — a gate with `detect_only:true`, `expected_evidence`, `why_it_might_fail` renders the badge and both lines; a gate without them renders neither and still shows Approve/Deny.
- [ ] **Step 2: Run, verify fail** — `npm run test` → FAIL.
- [ ] **Step 3: Implement** the type + card additions (reuse existing glass classes; append a small `.badge-detect` rule to `glass.css` if needed).
- [ ] **Step 4: Run tests + typecheck** — `npm run test`, `npx tsc -b`, `npm run build` all clean; `frontend/dist` untracked.
- [ ] **Step 5: Commit** — `feat(dashboard): show detect-only badge, expected evidence and failure note on gates`.

---

### Task 7: README + end-to-end smoke

**Files:** Modify `README.md`.

**Interfaces:** Produces the documented flow and a verified run.

- [ ] **Step 1: README** — add a "Human-gated verification (Phase 5)" section: `ascent run … --propose` writes proposed detect-only gates; open the dashboard, review each (command, target, expected evidence, why-it-might-fail, in-scope), Approve or Deny; `ascent verify --engagement … --out out` then runs ONLY approved, in-scope, hash-bound, detect-only nuclei re-checks and records Confirmed/NotConfirmed/Refused to the audit log. State the invariants: nothing runs without approval; an edited gate is refused; scope re-checked at execution; detect-only allow-list; hard exclusions not built.
- [ ] **Step 2: Smoke** — with a lab target (e.g. Juice Shop) and nuclei installed: `ascent run --engagement <lab> --out out --propose`; confirm `out/gates.json` has proposed detect-only gates. Approve one via the dashboard (or a curl `POST /api/gates/<id>/approve` with the `Origin`+`X-Ascent` headers). Run `ascent verify --engagement <lab> --out out`; confirm it ran only the approved gate, recorded a `gate_execution` entry, `crux::AuditLog::verify()`/the dashboard audit tab still shows chain OK, and that approving nothing (or denying) runs nothing. If no lab target is available, run the executor-path with a fake-free `--dry-run`-style check is NOT possible (it needs nuclei); document what was run. Also verify tampering: edit an approved gate's `args` in gates.json and confirm `verify` Refuses it.
- [ ] **Step 3: Commit** — `docs(verify): document and smoke the human-gated verification flow`.

---

## Self-review (coverage)

- Spec "gate contract (inert proposed action)" → Task 2 (model) + Task 3 (proposer writes it). "Lifecycle propose→approve→execute→audit" → proposer (3), the existing dashboard approve flow (reused, Task 1 shares its primitives), executor (4), CLI (5). "Detect-only MVP, allow-listed" → Task 2 allow-list + Task 4 enforcement. "gate_hash binding / refuse edited gate" → Task 4 (satisfies `docs/followups-dashboard.md` #1). "Scope re-checked at execution" → Task 4 via `ToolRunner`. "Audited" → Task 1 `append_chained` + Task 4. "Dashboard shows the proposal detail" → Task 6.
- Safety: nothing runs without a recorded approval (Task 4 gate on `approved_decisions`); argv-only, no shell; allow-list + scope + hash all checked before any spawn; one gate at a time; detect-only tool set (nuclei detection re-check) only; hard exclusions (C2/lateral/persistence/exfil/privesc/exploit-tier) explicitly out of scope.
- Deferred to later plans (own specs): the LLM-advised proposer (data-governed); the exploit tier (PoC tools) behind the same gate; Phase 6 post-exploitation; the cross-process audit lock (followups-dashboard.md) before concurrent run+verify.
- Verify in Task 5 how `run` obtains the triaged items for `--propose` (re-read `queue.json` rather than change `run_pipeline`'s signature); in Task 1 that the dashboard's 62 tests still pass after the primitives move.
