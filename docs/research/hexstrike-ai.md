# Reference memo: HexStrike AI (0x4m4)

Clean-room reference note. Source: public GitHub page, README and LICENSE only, read 2026-10-06. No source code was cloned, read or copied. Everything below is paraphrase.

Repo: https://github.com/0x4m4/hexstrike-ai

## Purpose and licence

A framework that exposes a large catalogue of security tools to AI assistants (Claude, GPT, Copilot and similar) through the Model Context Protocol, so the assistant can run assessments largely on its own: bug bounty, CTF and vulnerability research. It advertises over 150 integrated tools and a dozen specialised agents.

**Licence: MIT** (confirmed from the repo's LICENSE file; README attributes it to OTT Cybersecurity LLC). Note: this is NOT AGPL, contrary to the expectation that two of the three repos would be AGPL. The other two (Pentest-Swarm-AI, Shannon) are AGPL-3.0.

Implication for Ascent: MIT is permissive, so copying code is legally possible provided the copyright and licence notice are preserved. Ascent's policy is still to learn, not copy: this project's value to us is as a map of what to exclude, and its README makes unverified performance claims. Do not paste or translate its code; if anything were ever taken, MIT attribution would be required, and we do not plan to.

## Architecture and orchestration patterns

- **MCP bridge.** A local server presents tools to an AI client over MCP. The model asks for a capability; the server runs the underlying tool and returns output.
- **Decision engine.** A layer that looks at the target and context, picks tools and tunes their parameters, and sequences commands based on what earlier steps discovered.
- **Specialised agents.** Roles split by task type (vulnerability analysis, exploit development, CTF solving, bug-bounty workflow), coordinated through the central engine.
- **Tool catalogue by category.** Network recon, web testing, authentication attacks, binary analysis, cloud security, forensics/OSINT.
- **Operational plumbing.** Result caching, real-time process management and monitoring, resource-aware throttling, error recovery and graceful degradation, plus a live dashboard to watch agent activity.
- **Authorisation posture.** Documentation states use is limited to written-permission testing, legitimate bounty programmes, competitions and owned systems, and it recommends isolated or VM environments. From the public docs this is a policy statement; no technical scope-enforcement mechanism is described.

## Mapping to Ascent's stance

Deliberately EXCLUDED (studied only to define the exclusion):
- Handing an LLM an unconstrained toolbox of 150+ offensive utilities with the model choosing and chaining them.
- Exploit-development and autonomous exploitation agents; authentication-attack tooling driven without a human gate.
- Reliance on a policy paragraph for authorisation instead of enforcement at execution. This is the key contrast: Ascent enforces scope technically, in the executor.
- Headline detection-rate marketing claims; Ascent should report measured, reproducible results only.

Safe to reimplement clean-room:
- Exposing Ascent's read-only and approval-gated capabilities to an AI client via MCP, with every call routed through the scope-checking executor.
- Tool registry organised by category with declared metadata (risk class, whether it mutates state, required approval level).
- Result caching keyed on target and parameters to avoid repeat scans.
- Process supervision: timeouts, resource limits, kill-on-abort, graceful degradation when a tool is missing.
- Live activity view for the human operator (Ascent's dashboard already goes this way).

## Clean-room boundary

May reimplement under Apache-2.0 from our own design:
- An MCP front end with scope-gated tool calls; a typed tool registry with risk classes; caching; process supervision; operator activity feed.

Must never be copied or ported:
- Their source (even though MIT permits it with attribution, project policy is no copying), tool wrappers, parameter-tuning tables, agent prompts, MCP tool schemas and descriptions, README text and branding.
- Their autonomous exploit and attack-chain features (excluded by Ascent policy).

## Access notes

GitHub page, raw README (master branch) and raw LICENSE fetched successfully. Source files were not read. Claims in the README (tool count, detection rate) are the project's own and unverified.
