# SAST stage (white-box source analysis): design

Status: direction approved by the author on 2026-10-06. Origin: the one aligned idea from the Strix adoption study (`docs/research/strix-adoption.md`) — run static source analysis before/alongside dynamic testing and feed it into triage — reimplemented clean-room. This is Ascent's long-planned SAST track (PRD §3b, roadmap R1). No Strix runtime or code is used.

## Goal

Add a white-box track: when source code is available and authorised, Ascent runs static analysers over it, normalises their output into the existing `Finding` shape, and hands those findings to Crux for triage alongside the DAST findings. One ranked, audited queue covers both tracks.

## Principles kept (unchanged from the core)

- **Invoke, don't vendor.** Each analyser is an external binary run as a subprocess through the scope-checked runner. Nothing copyleft is linked into Ascent. (opengrep, gitleaks and trivy are the PRD's chosen SAST-track tools; whichever is used is invoked, never vendored.)
- **Scope at the execution boundary.** Source analysis does not touch a network target, so the network `ScopeGuard` does not apply to it. Instead a **source-scope check** refuses to analyse any path outside the engagement's authorised `source` root. The stage passes no network targets to the runner.
- **Human-in-the-loop, audited.** SAST findings are triaged by Crux (its original `file:line` mode) and written to the same hash-chained audit log and ranked report. No exploitation; static analysis only reads code.
- **Data governance.** The MVP of this stage makes no external LLM call: Crux triage runs offline (`MockTriager`). Source code never leaves the machine.

## Tools (all invoked as subprocesses)

- **opengrep** — pattern/taint static analysis (the maintained, non-license-trap fork of the semgrep engine). Emits SARIF/JSON. (Confirm opengrep's own licence during implementation; it does not matter for Ascent because it is invoked, not linked, but it must not be a bundle-forbidden tool.)
- **gitleaks** — secret scanning (MIT). Emits JSON.
- **trivy** — dependency/SCA and SBOM (Apache-2.0). Emits JSON.

Each is optional at runtime: a missing tool makes its sub-stage report `skipped`, not a hard failure (unlike nuclei, which is security-critical and version-gated). None is bundled; the README documents installing them.

## Architecture

### Engagement gains a source root

`Engagement` gains an optional `source: String` (a local directory path). An engagement with a `source` is eligible for the SAST track. The source-scope check canonicalises both the configured root and any path handed to an analyser and refuses anything not inside the root (defends against `..` traversal and symlink escape).

### New stage module `src/stages/sast.rs`

- `fn sast(runner: &dyn Runner, source_dir: &str) -> Result<Vec<Finding>, Box<dyn Error>>` — runs each available analyser over `source_dir` (via `runner.run_json`, no network targets), normalises each tool's output, returns the merged `Vec<Finding>`. A sub-stage whose tool is absent is skipped.
- Per-tool availability is checked the same way the DAST stage checks nuclei's presence.

### Normalisers (extend `src/normalise.rs`)

- `normalise_opengrep(rows) -> Vec<Finding>` — `category = "SAST"`, `file`/`line`/`rule_id`/`severity`/`cwe` from the SARIF/JSON result; `url` empty. Crux's `locus()` already returns `file:line` for these.
- `normalise_gitleaks(rows) -> Vec<Finding>` — `category = "SAST"` (secret), `file`/`line`, `rule_id` = the rule, evidence redacted (store the rule and location, never the raw secret value).
- `normalise_trivy(rows) -> Vec<Finding>` — `category = "SCA"`, `rule_id` = the CVE/advisory id, `file` = the manifest, `cwe` where given.
These map onto the existing `Finding` struct (which already has `file`, `line`, `category`, `cwe`) and `to_crux_json()`; Crux already accepts `SAST`/`SCA` categories.

### Pipeline integration (`src/pipeline.rs`)

- `run_pipeline` gains a source root (from the engagement, or a `--source` override). The DAST track (recon → enumerate → scan) runs as today. When a source root is present, the **SAST track runs too** and its findings are concatenated with the DAST findings before triage. Either track may be empty.
- Triage, report and audit are unchanged: they already operate on a `Vec<Finding>` regardless of track. The report groups by verdict as now; the finding's `category` distinguishes SAST/SCA/DAST.
- Conditionals: skip the SAST track entirely when no source root is configured; skip a sub-stage when its tool is missing; skip triage when there are no findings at all.

### CLI (`src/main.rs`)

`ascent run` gains `--source <dir>` (overrides the engagement's `source`). Everything else is unchanged. `--dry-run` skips the analysers (as it skips scanners today).

## Testing

- Pure normalisers: a captured sample of each tool's JSON → expected `Finding`s (incl. the secret-redaction rule: gitleaks findings never carry the raw secret).
- `sast()` with a fake `Runner`: all tools present → merged findings; a tool "absent" → that sub-stage skipped, others still run; no tools → empty.
- Source-scope check: a path inside the root is allowed; `..` traversal, an absolute path outside, and a symlink pointing outside are all refused.
- Pipeline: a fake runner that returns SAST + DAST rows → both tracks' findings reach triage and the report; a source-less engagement runs DAST only; `--dry-run` runs neither analyser.
- No network target is ever passed for a SAST sub-stage (assert the runner received empty targets), so the stage can't accidentally reach the network.
- Licence/secret safety: a test asserting a gitleaks finding's serialised form contains the rule and location but not the secret value.

## Out of scope (deferred, as before)

Exploitation/post-exploitation; any external-LLM triage of source (data-governance work comes with the later Claude advisory layer); SAST-reachable + DAST-confirmed correlation (a later refinement once both tracks exist); the dashboard showing a per-track filter (a small later UI follow-up). The MVP of this stage is: run the analysers, normalise, triage offline, report.

## How it merges with the existing plans

This is the SAST track the PRD and roadmap already reserve (PRD §3b, R1). It slots beside the pipeline-core plan as a second track into the same Crux triage, needs no change to triage/report/audit, and is independent of the dashboard. It will be written as its own implementation plan (`docs/plans/2026-10-06-ascent-sast-track.md`) and listed in the roadmap as delivered when done.
