# Ascent research notes (clean-room references)

These are clean-room reference notes written from public READMEs, licence files and GitHub pages only. No source code was cloned or copied, and none is reproduced here. Ascent (Apache-2.0) may learn ideas and patterns from these projects, but must never copy or port their code. Translating copyleft source into Rust does not launder the licence: the result is still a derivative work bound by the original terms, and a repo being public does not change that. Implement from Ascent's own design, not with the other project open.

Ascent's stance, for contrast: human-in-the-loop, scope enforced at the execution boundary, and no autonomous exploitation, lateral movement, C2, persistence or exfiltration.

| Repo | Licence | One-line takeaway |
|------|---------|-------------------|
| [Pentest-Swarm-AI](pentest-swarm-ai.md) | AGPL-3.0 | Shared findings store with decaying weights and trigger-based agents; scope checked at both tool setup and execution; reverse-order cleanup registry. |
| [HexStrike AI](hexstrike-ai.md) | MIT (not AGPL) | MCP front end over a categorised tool registry with caching and process supervision; its authorisation is policy text only, which is what Ascent's enforced scope replaces. |
| [Shannon](shannon.md) | AGPL-3.0 (plus commercial licence) | Phased pipeline with a reconcile-and-dedupe step and proof-gated findings, ephemeral sandboxes and resumable runs; Ascent keeps a human gate where it exploits. |

Each memo lists what Ascent deliberately excludes, what is safe to reimplement independently, and a short clean-room boundary.

Research date: 2026-10-06.
