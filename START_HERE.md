# Ascent — start here (for a fresh dev session)

Ascent is an open-source, AI-assisted, **human-in-the-loop** AppSec/pentest pipeline. It orchestrates OSS scanners, normalises findings, triages them through **Crux** (a separate existing project), and keeps a human on every destructive action, within an enforced scope. Apache-2.0. Author: Dennis Liu (Chang Liu) / SecBlok.

**Crux vs Ascent:** Crux (`M:/Projects/crux`, formerly the "jev" placeholder) is the AI *triage layer* (a component). Ascent is the *pipeline* that uses Crux as its triage stage. Two distinct products, both the author's, both open-source.

**Crux is already built — do not rebuild it.** It is a finished **Rust** crate (library + `crux` CLI) in its own repo (`M:/Projects/crux`, GitHub `Aldiharley/crux`) with its own `README.md`, code, and tests; the original Python implementation is kept as a reference in `crux-python/`. Read `M:/Projects/crux/README.md` before extending it. Ascent links it as a **library** (path dependency `crux = { path = "../crux", default-features = false }`) and calls `crux::triage` in-process. URL-based DAST findings and the `--emit-json` queue export (pipeline-core **Task 7**) are already in Crux. There is no "build Crux" plan here because Crux already exists.

## Read these first, in order
1. `PRD.md` — the full spec (problem, architecture, phases, safety, licensing, MVP + roadmap).
2. `TOOLS.md` — the tool arsenal with licenses and the bundle / invoke / avoid classification.
3. `docs/plans/2026-10-04-ascent-mvp-pipeline-core.md` — the pipeline-core plan (11 TDD tasks). **Done:** built on `main`; post-MVP follow-ups are in `docs/followups-pipeline-core.md`.
4. `docs/plans/2026-10-04-ascent-dashboard.md` — the dashboard plan (axum + React + Fluid Glass), build after the pipeline core.

## Design
- The dashboard's visual design is the **Fluid Glass** style. The source of truth is `design/dashboard-mockup.html` (also published as a private artifact for viewing). The dashboard plan says to port its token system and glass primitives into React, not redesign.
- The core UI needs **no image assets** (pure CSS). If optional extras are wanted (favicon/logo mark, empty-state art, OG image), generate them with the **Higgsfield CLI** (`@higgsfield/cli`; models `nano_banana_pro`/`flux_kontext`/`nano_banana_flash`, upscale to 2k/4k) and record the prompt + model in `design/ASSETS.md`.

## How to build
- Follow the plan **one task at a time, TDD** (write the failing test, see it fail, minimal code, see it pass, commit). Steps are checkboxed.
- Use the **subagent-driven-development** skill (recommended: fresh subagent per task, review between) or **executing-plans** (inline with checkpoints).
- Start by scanning the repo state; if this is a new repo, Task 1 scaffolds it.

## Language and Claude integration
- **Ascent is built in Rust** (cargo, single binary). It drives the external scanners as **subprocesses** through the scope-checked `ToolRunner`; it never imports or vendors them. **Crux** (the author's own Apache-2.0 crate) is the one exception: it is linked as a library with default features off, so its HTTPS client is compiled out and the Ascent binary carries no network code.
- **Claude still drives the whole pipeline** (building in Rust changes plumbing, not capability): Ascent exposes an **MCP server** (Rust `rmcp` SDK) so **Claude Code, on your Claude plan, drives the stages**; and Ascent can call the Anthropic API over HTTPS (`reqwest`, API key) for internal advisory steps. Both are post-MVP (later plans). The MVP has no LLM call (triage uses Crux's offline `MockTriager`).

## Prerequisites
- Rust stable + cargo; `cargo clippy`, `cargo fmt`.
- Install the external tools (invoked, never vendored): subfinder, dnsx, httpx, katana, ffuf, and **nuclei >= v3.10.0** (CVE-2026-76802 is checked at runtime). `pdtm` installs the ProjectDiscovery ones.
- **Crux is a path dependency:** keep the crux repo checked out next to Ascent (`M:/Projects/crux` beside `M:/Projects/Ascent`). Cargo builds it; no Python is needed. CI checks out `Aldiharley/crux` alongside Ascent, so crux's `main` must be pushed for CI to pass.
- Only ever run against an **authorised / lab target** (OWASP Juice Shop or WebGoat.NET for the MVP smoke run).

## Non-negotiable guardrails (from the PRD)
- Apache-2.0 core; invoke copyleft tools as subprocesses, never vendor their source; never bundle license-trap tools (CodeQL on client code, Brakeman, WPScan commercial).
- Scope enforced at the execution boundary (the `ToolRunner` hook) on every tool call. No tool called directly.
- No autonomous exploitation; no automated lateral movement, C2, persistence, or exfiltration. (None are in this MVP plan anyway.)
- IP: built pre-employment on own equipment; add Ascent (and Crux) to the employment IP Schedule 1; disclose authorship to the employer; never send employer code/data to an external LLM without sign-off.

## What's deferred to later plans
SAST track (3b), exploitation/post-exploitation (5-6), the MCP server (Rust `rmcp`, so Claude Code drives Ascent), and the `reqwest`/local-LLM advisory calls. (The pipeline-core and dashboard plans are both written, see "Read these first".)

## Open decisions (defaults assumed in the plan)
Name: Ascent (provisional). MVP target: WebGoat.NET or Juice Shop. MVP: CLI spine first, dashboard next. Store: Crux now, DefectDojo later.
