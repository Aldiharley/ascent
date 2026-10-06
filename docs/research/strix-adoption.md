# Strix adoption feasibility

Status: research memo, not committed. Sources: public GitHub repo page, the LICENSE file (raw), README, and the public docs at docs.strix.ai (index at /llms.txt, plus CLI, scan-modes, tools/sandbox, integrations/mcp, advanced/configuration, llm-providers/overview, cloud/overview). No source code was cloned or read. All content below is paraphrased. Page content was retrieved through a summarising fetch tool, so exact flag names and defaults should be re-verified against the live docs before any design depends on them.

## 1. Licence (verified)

- The `LICENSE` file at the repo root is the standard, unmodified Apache License, Version 2.0 (January 2004). Only the usual appendix-style notice differs: copyright holder is OmniSecure Inc., year 2025. The README also states Apache 2.0.
- Consequence for Ascent: Ascent is Apache-2.0, so depending on Strix, invoking it, or incorporating code from it is licence-compatible provided Apache-2.0 obligations are met (retain the licence text and copyright/NOTICE, mark modifications, no trademark use of the Strix name or logo beyond fair description). Per Ascent's architecture we should still prefer a subprocess or clean interface over vendoring source.
- Caveats to check: (a) the licence covers the repo, not its dependencies, the sandbox image, or the bundled Kali tools. The sandbox image pulls many third-party tools under their own licences (some copyleft, e.g. SQLMap, Nmap's custom licence, ZAP, Wapiti). That is fine for a subprocess/container boundary Ascent does not redistribute, but Ascent must not bundle that image. (b) Strix Cloud is a separate commercial service with its own terms. (c) Strix is Python; the dependency set (LiteLLM etc.) was not audited here.

## 2. What Strix is

Strix is an open-source "AI hacker" agent platform. It describes itself as autonomous agents that run code dynamically, find vulnerabilities and validate them with proofs of concept. Maintained by OmniSecure; also has a hosted cloud product (app.strix.ai).

Architecture as publicly documented:
- Language and install: Python, published to PyPI as `strix-agent`; installed with a curl-pipe-bash installer from strix.ai. Requires a local Docker daemon and an LLM API key.
- Orchestration: a "graph of agents" model. A coordinating agent spawns specialised agents (recon, exploitation, post-exploitation are named in the README) that run in parallel, share discoveries and chain findings.
- LLM usage: all reasoning is done by an LLM through LiteLLM, so 100+ providers (OpenAI, Anthropic, OpenRouter, Vertex, Bedrock, Azure, DeepSeek, local Ollama / LM Studio / OpenAI-compatible endpoints). Default model is a hosted one via OpenRouter. Configuration via `STRIX_LLM`, `LLM_API_KEY`, `LLM_API_BASE`, or `~/.strix/cli-config.json`.
- Tools given to agents: Caido-based HTTP proxy (intercept and replay), Playwright browser, an interactive terminal (bash), a Python runtime for writing PoC code, source editing, web search (Exa or Perplexity, optional), notes, and a vulnerability-report tool.
- Sandbox: a Kali-Linux-based Docker container with a large pre-installed toolkit, including subfinder, httpx, katana, ffuf, nmap, naabu, nuclei, sqlmap, ZAP, Wapiti, semgrep, trufflehog, gitleaks, trivy, jwt_tool, interactsh. The agent chooses which to run. The public docs do not describe the container's network policy or egress restrictions.
- Targets: local directories, git repos, live URLs/domains/IPs, OpenAPI/Postman specs. Source-aware ("white-box") plus dynamic testing.
- Scan modes: quick (minutes, CI/PR use), standard (about 30-60 min), deep (1-4 h, default); deep includes chained-vulnerability and edge-case exploration.
- Interfaces:
  - CLI `strix` with `--target`, `--target-list`, `--scan-mode`, `--scope-mode` (auto/diff/full), `--diff-base`, `--instruction`/`--instruction-file`, `--workspace-file`, `--max-budget` (USD cap), `--max-turns` (per agent, default 500), `--non-interactive`, `--fail-on <severity>`, `--config`, `--mcp-server`/`--mcp-exclude`.
  - Headless exit codes: 0 ok, 1 fatal error, 2 findings at or above threshold.
  - Local artifacts in `strix_runs/<run>/` including an `events.jsonl` event log; `strix view` serves a local dashboard on 127.0.0.1.
  - Strix is an MCP client (it can consume MCP servers from `~/.strix/mcp-servers.json` with an `allowed_tools` list). I found no evidence it is an MCP server. A coding-agent "skill" package exists for Claude Code/Cursor/Codex that teaches those tools to drive Strix.
  - A hosted REST API exists for Strix Cloud; I could not retrieve endpoint details. No documented stable in-process library API for the open-source CLI.
  - GitHub Actions / CI integration with diff-based scoping on pull requests.
- Telemetry: controlled by `STRIX_TELEMETRY`, covering PostHog, Scarf and OpenTelemetry; remote tracing export is opt-in via Traceloop variables. A local JSONL event log is always written. The default state of telemetry was not stated in what I retrieved.

## 3. Fit against Ascent's five principles

### 3.1 Principle 1 (AI advises, human executes)
Direct conflict at the product's core. Strix's value proposition is that LLM agents act on the target without a human in the loop: spawn exploitation and post-exploitation agents, run shell commands, write and execute PoC code, drive a browser and replay traffic through a proxy. "Validate through actual proof-of-concept" means live exploitation. The only human controls documented are start-time ones (target selection, an instruction string, budget and turn caps), not per-action approval. Headless mode (`-n`) removes even the interactive display. The 500-turn-per-agent default and deep-mode chaining indicate extended unattended operation.

### 3.2 Principle 2 (scope enforced at the execution boundary)
Not compatible as shipped. Observed scope features are advisory or coarse: the target list given at start, `--scope-mode diff` (which scopes which code changes to test, not which hosts a tool may touch), and natural-language instructions. The agent holds a general bash shell and a Python runtime inside a Kali container, and can run nmap, sqlmap, ffuf, etc. against whatever it decides to. I found nothing in the public docs about a deterministic per-tool-call allowlist, an egress firewall on the sandbox, or verification of a signed engagement. Scope therefore depends on LLM compliance with prompt text, which is exactly what Ascent's principle rejects. (Absence in public docs is not proof of absence in code; this is an open question, below.) The MCP `allowed_tools` field is a tool-name allowlist, not a target-scope check, and the docs themselves say Strix does not classify which tools are read-only.

### 3.3 Principle 3 (human approval before state-changing actions)
No documented approval gate. State-changing actions (exploit attempts, sqlmap data extraction, form submissions in the browser, writes through connected MCP servers) occur at the agent's discretion. The cost and turn caps are budget controls, not approval gates.

### 3.4 Principle 4 (hash-chained audit)
Strix writes a local `events.jsonl` and run artifacts, which is useful raw material, but nothing documented is tamper-evident or hash-chained, and it records Strix's own view of events. Ascent would need to wrap the call and chain-log at its own boundary, not rely on Strix's log.

### 3.5 Principle 5 (clean licensing, subprocess invocation)
Compatible. Apache-2.0 itself is clean. Subprocess invocation of the `strix` CLI (itself spawning Docker) matches the "external tools as subprocesses" rule. Watch-outs: do not vendor or redistribute the sandbox image; pin a version; treat the curl-pipe-bash installer as an untrusted-source download needing a human decision (prefer `pip`/`uv` install from PyPI with pinned hash, in a venv).

## 4. Capabilities: aligned versus conflicting

### 4.1 Aligned (adoptable, with where in the pipeline)

| Strix capability | Ascent stage | Form of adoption |
|---|---|---|
| Recon/enum/scan tools (subfinder, httpx, katana, nuclei, ffuf) | recon, enumerate, scan | Ascent already runs these directly; no reason to route through Strix. Confirms tool choice only. |
| Source-aware static triage (semgrep, AST search, secrets, trivy) before dynamic work | new SAST/source stage (adjacent to scan) | Pattern to reimplement, or run those tools directly as subprocesses. Ascent currently has no source stage; this is the most additive idea. |
| White-box + black-box correlation (use source to prioritise dynamic checks) | triage | Pattern for Crux: use code findings to rank DAST findings. Clean-room. |
| Findings with severity, CVSS/OWASP mapping and PoC narrative in a report | normalise / report | Pattern; map to Ascent's normalised finding schema. Do not import Strix's report format as authoritative. |
| `--fail-on` severity exit-code gating, diff-scoped quick scans | CI integration | Pattern for an Ascent CI mode (read-only DAST on PRs). |
| Run budget (`--max-budget`) and turn caps | any LLM-driven stage | Pattern: Ascent's own LLM triage/advice calls should have cost and iteration ceilings. |
| Local-only viewer bound to 127.0.0.1 with tokenised link | dashboard | Pattern consistent with Ascent's local dashboard. |
| Local-model support via LiteLLM-style provider abstraction | triage / advice | Pattern: let operators point LLM calls at a local endpoint to avoid sending target data off-box. |
| Upfront manifest and hash of what will be uploaded, approved before transmission (Strix Cloud) | any external data egress | Good governance pattern worth copying for Ascent's own egress approvals. |

### 4.2 Conflicting (exclude, or only behind the gate)

- Autonomous exploitation and post-exploitation agents, chained exploitation: exclude entirely from any default or unattended path. This is the clearest conflict.
- Free-form agent bash and Python runtime executing against targets: only acceptable if every command is a proposal that a human approves verbatim and the scope wrapper checks it first (Ascent's deferred "Claude proposes an exact command" design). Strix does not support that mode; it would have to be reimplemented, not driven.
- sqlmap and other state-changing or data-extracting tools running at agent discretion: exclude from automated use.
- Browser automation acting on the live app (form submits, auth flows): state-changing; gate it.
- Writes through arbitrary connected MCP servers: exclude; Strix explicitly leaves read/write classification to the user.
- Strix Cloud: sends source and results to a third party; out of bounds for an engagement without explicit client consent.
- Default-on third-party telemetry and default hosted LLM: unacceptable defaults for client data.

### 4.3 Scope compatibility verdict
Strix assumes it is pointed at assets the operator owns and then given free rein within them; it enforces authorization by policy statement ("only run against systems you have written permission to test"), not by mechanism. It is not designed around enforcement at the execution boundary. Ascent could place a boundary outside Strix (network egress restricted to in-scope hosts, a pre-flight check of the target list against the signed engagement), but it could not intercept individual tool calls inside the agent loop, so per-call scope enforcement would be only partial (network-level) and could not stop an in-scope-host but out-of-bounds action type.

## 5. Data governance

- Strix sends prompts to whatever LLM is configured. The public docs do not enumerate what goes into those prompts, but in practice agent context includes target responses, request/response bodies, source code snippets, discovered credentials/tokens and tool output. Assume target data (potentially personal data and secrets) leaves the machine for a third-party provider unless a local model is used.
- The default model path is a hosted multi-provider gateway (OpenRouter), which adds a further intermediary.
- Optional external services: Exa/Perplexity web search (queries may include target identifiers), PostHog/Scarf/OTEL telemetry, Traceloop remote tracing.
- Strix Cloud receives uploaded source snapshots (with a documented dry-run manifest and SHA256 approval step, a good control) and scan results.
- For Ascent: any adoption must run with telemetry off, no remote tracing, no web search tools, and either a local model or a provider covered by the client's data-processing terms. Engagement contracts should state whether target data may go to an external LLM. This aligns with Ascent's existing posture that AI advises from normalised findings, not raw target traffic.

## 6. Options and recommendation

### Option (a): adopt as a gated subprocess tool
Only a narrow form is defensible: run Strix (or better, just its static/source-analysis components) in a read-only, non-exploiting configuration as an optional "source review / white-box hints" stage, producing findings that enter normalise and triage as untrusted advisory input.
- Integration point: a new optional stage between enumerate and scan (or parallel to scan) in the CLI, invoked as `strix` subprocess with `--non-interactive`, `--scan-mode quick`, a source-directory target only (no live URL), a hard `--max-budget`, local model or approved provider, telemetry disabled, no MCP servers, no web-search keys.
- Controls required:
  - Scope wrapper: refuse unless the target (path or repo) is named in the signed engagement; for any live-URL target, additionally refuse unless the host is in scope; run the container with network egress denied except to the LLM endpoint (and, for live targets, only in-scope hosts) enforced outside Strix (firewall, Docker network policy).
  - Approval gate: human approves the exact command line, target list, model endpoint and budget before launch (this is a state-changing/egress action even for source-only runs); no live-target run without a separate approval.
  - Audit: hash-chain the approved invocation, arguments, versions, image digest and exit code, plus a digest of the output artifacts; import `events.jsonl` as attachments, not as the audit of record.
  - Output handling: treat Strix findings as claims, re-verify through Ascent's own pipeline; never auto-promote to exploitation.
  - Risk: even with `quick` mode the agent has a shell and could act beyond intent; this option leaves residual risk because the agent loop cannot be gated per call. That is why source-only plus network-denied is the minimum.

### Option (b): reimplement selected patterns clean-room
Recommended. Candidates: source-aware static triage stage (invoke semgrep, gitleaks/trufflehog, trivy directly as subprocesses, each scope-wrapped and audited); correlation of static findings with DAST findings inside Crux; severity-threshold exit codes for CI; run-level LLM budget/turn caps; manifest-and-hash approval before any external data egress; local-model provider abstraction for advice calls; PoC narrative fields in the report schema (as human-authored or human-approved text).
- Integration points: new `source` recon-adjacent stage, Crux triage, report, CI mode.
- Controls: same scope wrapper, approval gate and audit chain Ascent already applies to subfinder/httpx/katana/nuclei; no new trust boundary introduced.
- Implementation should work from the documented behaviour above and the underlying open tools' own documentation, not from Strix source.

### Option (c): do not adopt / defer
Appropriate for everything in section 4.2. Exploitation and post-exploitation remain deferred; when built, they follow Ascent's propose-exact-command, human-approve, then execute model. Strix's agent loop is the opposite shape and is not a base for it.

### Headline recommendation
Defer Strix as a runtime dependency, and take option (b): reimplement the source-aware static triage stage and a few operational patterns clean-room as direct, scope-wrapped subprocesses. Keep option (a) as an optional, human-approved, source-only experiment after the open questions below are answered. Never enable the exploitation/post-exploitation agents or the live-target agent loop inside Ascent.

## 7. Open questions for a human

1. Is Ascent willing to ship, even optionally, an integration with a tool whose core design is autonomous exploitation, given the "AI advises, human executes" principle? Or should it be limited to reimplemented patterns only?
2. Does Strix have any enforced (not prompt-level) target restriction, such as a host allowlist or egress policy in the sandbox? Needs source or maintainer confirmation; the public docs say nothing. Would a custom sandbox image/network policy be acceptable?
3. What exactly is sent to the LLM in each run (prompt contents, tool output, source), and what are the defaults for `STRIX_TELEMETRY` and the default model route? Needs a controlled test with a proxy on a throwaway target.
4. Which LLM endpoint is acceptable for client data: local model only, a named provider with a DPA, or none? Does the engagement template need a data-egress consent clause?
5. Can we get a non-interactive mode that proposes actions and waits for approval, or is that infeasible without forking? (If it needs a fork, it is effectively option (b).)
6. Is the curl-pipe-bash installer and the pulled Docker image acceptable under Ascent's "no downloads from untrusted sources" posture? Who vets and pins the image digest, and who tracks licences of the bundled Kali tools?
7. Maintenance and governance risk: single-vendor project (OmniSecure) with a commercial cloud; what is the fallback if the licence or direction changes? Fast-moving model/provider defaults suggest frequent breaking changes.
8. Do we want a source-analysis stage at all in the current roadmap, and should its findings feed Crux triage or stay separate?
9. Legal: any need for client consent specific to source-code access plus third-party LLM processing?
10. Is a CI/PR read-only DAST mode in scope for Ascent, and if so is it fine to expose it without the interactive approval gate (what is the gate in CI)?

## 8. Sources and gaps

Retrieved: github.com/usestrix/strix (repo page), raw LICENSE and README, docs.strix.ai pages: index, llms.txt, usage/cli, usage/scan-modes, tools/overview, tools/sandbox, integrations/mcp, advanced/configuration, llm-providers/overview, cloud/overview. Not retrieved or not detailed: the internal agent-graph design, sandbox network policy, exact prompt/data content sent to LLMs, REST API endpoints, telemetry defaults, dependency licence audit. These are recorded as open rather than assumed. Short quote, attributed to the Strix README: "Authorized use only."
