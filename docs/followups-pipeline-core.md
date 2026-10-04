# Ascent pipeline-core — post-MVP follow-ups

From the final whole-branch review of `feat/mvp-pipeline-core` (all non-blocking; the MVP is merge-ready and all four safety properties hold). Ordered by recommended priority.

1. **Sample engagement / `eng.urls` ignored.** `run_pipeline` uses recon-from-root whenever any host is set and ignores `eng.urls` (`src/pipeline.rs`). `samples/engagement.example.yaml` lists both `hosts: [localhost]` and `urls: [http://localhost:3000/]`, so a live run against OWASP Juice Shop (:3000) may probe default ports via httpx and find nothing. Fix: either also seed the scan surface from `eng.urls`, or ship a sample whose root host exposes the service on a probed port, and document it.
2. **katana off-site endpoints can abort the scan (fail-closed).** `enumerate_surface` merges all discovered `endpoint`s unchecked; `scan` then gates their hosts, so one off-scope link makes the whole nuclei call refuse and the pipeline error out. Fix: filter merged endpoints to in-scope hosts instead of aborting.
3. ~~**Crux spawned outside `ToolRunner`.**~~ **Resolved:** Crux is now linked as a library (`default-features = false`), so there is no Crux process to gate and no network code in the binary. If an LLM triager is ever enabled, it must go behind the data-governance gate (PRD section 4).
4. **Scope config hardening.** Add `#[serde(deny_unknown_fields)]` to `Engagement` so a misspelled scope key (which silently shrinks scope — fails safe but quietly) becomes a loud error. Consider a scheme allow-list (http/https) and a resolved-IP re-check (DNS-rebinding) in `ToolRunner` for defense-in-depth.
5. **Cosmetic.** `audit.jsonl` path is printed even when no audit was written (dry-run / no findings); report fields are interpolated into markdown unescaped (local output); README "single static binary" is aspirational.

Deferred by design (per PRD/plan, not defects): time window not enforced; scope is lexical; triage runs Crux's offline `MockTriager`; no exploitation.

CI: `.github/workflows/ci.yml` checks out `Aldiharley/crux` next to Ascent for the path dependency. It goes green only once crux's Rust `main` is pushed (origin currently holds only the initial commit).
