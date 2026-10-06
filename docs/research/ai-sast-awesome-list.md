# Reference memo: scadastrangelove/awesome-ai-security-tools

Clean-room reference note. Source: the list's public README (pulled raw and read 2026-10-06) plus GitHub licence metadata and the linked projects' public READMEs. No source code was cloned, read or copied. Everything below is paraphrase. Licences for linked projects were taken from GitHub metadata or their README; where a value says "unverified" it was not confirmed.

Repo: https://github.com/scadastrangelove/awesome-ai-security-tools

## Licence and clean-room implication

The list itself is **CC0-1.0** (public-domain dedication), so mining it is unrestricted. The linked projects keep their own licences; the list's legend marks open-source (green), research, commercial-with-open-parts, and restrictive/unclear (warning). Each linked tool needs its own check.

## What it is

A large, curated, frequently refreshed index (most recent refresh in the file: 2026-10-05) covering autotriage, agent security, pentest agents, LLM fuzzing, SOC triage and more. The relevant sections are "AI-Powered SAST and Secure Code Review" and "Autotriage of Security Findings". Many entries carry caveats that matter to Ascent, repeatedly: hosted providers receive source, and local inference needs separately provisioned models.

## Most relevant tools (licence per GitHub metadata)

| Tool | Licence | Technique | Local model? | Fit for Ascent |
|---|---|---|---|---|
| Vulnhuntr (Protect AI) | **AGPL-3.0** | LLM call-chain tracing from remote input to server output; iteratively asks for more functions/classes; Python only, 7 vuln classes; confidence score | Experimental Ollama (weak structured output) | Best-known source-to-sink technique. **Copyleft: reimplement the idea only, never vendor or port.** Its README text lacks licence info; the GitHub metadata says AGPL. |
| VulnHunter (Capital One) | Apache-2.0 | Forward analysis from exposed entry points to sinks, then a falsification pass that tries to disprove each finding, then evidence-backed fix | No: built for Claude Opus inside Claude Code | The "VulnHunter" technique the PRD cites. Licence-clean to learn from; cannot be a local-model tool. |
| IRIS | MIT | Neurosymbolic: an LLM classifies APIs/params as taint sources/sinks/propagators, then CodeQL queries run, then an LLM filters FPs | Yes (Ollama, Qwen2.5-Coder, Llama) | Excellent design pattern (LLM infers specs, deterministic engine does the dataflow). Java and CodeQL-bound, research code. |
| Metis (Arm) | Apache-2.0 | Triages external SARIF with source-navigation evidence, tree-sitter chunking, optional C/C++ reachability graph | **Yes: Ollama and vLLM first-class** | **Strongest candidate to learn from or invoke**: consumes SARIF from opengrep, local-capable, Apache. |
| nano-analyzer (AISLE) | Apache-2.0 | Three stages: context briefing, scan, multi-round skeptical triage with grep verification and a confidence floor | Not documented (OpenAI/OpenRouter) | Cheap, small pipeline; the skeptical-triage stage is a good FP-control template. Per-file only, C/C++ focus. |
| seclab-taskflow-agent (GitHub) | MIT | YAML taskflows that triage CodeQL/SAST alerts and filter FPs | Provider-configurable (unverified for local) | Declarative taskflow idea; fits triage. |
| sast-ai-workflow (Red Hat) | Apache-2.0 | LangGraph workflow reviewing static-analysis findings to cut FPs | Unverified | Same shape as Metis; Python/LangGraph dependency. |
| Fraim | MIT | Workflows: PR risk flagger, code analysis, IaC; SARIF out | No local mention | Reference only. |
| llm-sast-scanner | MIT (README-stated) | Agent skill with structured source-to-sink checklists across 34 vuln classes | Depends on host agent | Useful class checklists to inform Ascent's own prompt rules (reimplement as own text). |
| sast-skills | MIT | Agent skills forming a multi-agent SAST scanner | Depends on host agent | Reference. |
| Clearwing | MIT | Ranks files, hunts, validates, optional patches, SARIF | Local providers supported | **Executes generated exploits/compiles targets: out of scope for Ascent's stance.** |
| deepsec (Vercel Labs) | Apache-2.0 | Coding-agent harness, resumable parallel runs, custom matchers, revalidation | Via the agent | Resumability pattern. Agent-driven, hosted-by-default. |
| Mantis (Google) | Apache-2.0 | Skills and harness: discovery, triage, reproduction, patching, deterministic gates | Hosted ADK models | Reference; reproduction executes code. |
| Visa agentic harness | licence field "none asserted" on GitHub; list says Apache-2.0 | Agentic SAST pipeline through remediation | Frontier models | Verify the LICENSE file before any reuse; remediation edits source by default: contrary to Ascent. |
| Anthropic defending-code-reference-harness | none asserted by GitHub (unverified) | Threat model, scan, triage, execution-verified memory bugs | Claude | Executes target code; sandbox needed. Reference. |
| Cloudflare security-audit-skill | MIT | Multi-phase audit: recon, coverage-led hunting, independent verification | Needs capable agent | Notable finding: one run finds only about half of what repeated runs find (nondeterminism). |
| Trail of Bits skills | share-alike terms flagged by the list | Review and false-positive workflows | Via agent | Share-alike: do not adapt text into Ascent. |
| Buttercup (Trail of Bits) | **AGPL-3.0** | Cyber reasoning system | Configured providers | Copyleft and heavy: avoid. |
| nuclei-autotriage | restrictive personal/non-commercial EULA | LLM triage of nuclei output | OpenAI-compatible (Ollama/vLLM) | **Licence trap: not usable.** DAST side only. |
| claude-code-security-review (Anthropic) | MIT | Claude-based PR diff review Action | No (hosted Claude) | Reference for prompt scoping to diffs. |
| open-kritt | list flags warning | Self-hosted orchestrator, root containers, sends code to provider | No | Unsafe defaults; avoid. |

(Also in the same section but not examined: Symfony Security Auditor with attacker/reviewer passes and an offline-only switch that defaults off; OpenHack; Codex Security CLI/SDK, which needs vendor access; Project CodeGuard, a CC BY 4.0 rules set referenced elsewhere in the list.)

## Cross-cutting observations

- Almost every entry is hosted-model-first; local support is the exception (Metis, IRIS, Rivian's Ollama option, Clearwing partly). This confirms data governance will be a differentiator for Ascent.
- Common pipeline shape across the field: **context building, detection, adversarial/skeptical validation, human review**.
- Several tools execute target code or edit source. Ascent's stance excludes that for the SAST track.
- The list's own caveats say model verdicts are not proof of exploitability.

## What Ascent should learn

Use the list as the radar for techniques, in priority order: (1) Metis for SARIF triage with local models, (2) IRIS for LLM-inferred source/sink specs over a deterministic engine, (3) VulnHunter/Vulnhuntr for entry-point-forward call-chain analysis plus falsification, (4) nano-analyzer's skeptical triage rounds and confidence floor.

## Subprocess or reimplement?

Metis could be invoked as an opt-in subprocess (Apache-2.0, Python, local-capable, SARIF in and out) but adds a Python dependency and its triage is aimed at C/C++ reachability. Everything else: reimplement the technique. Avoid AGPL entries (Vulnhuntr, Buttercup) as code sources.
