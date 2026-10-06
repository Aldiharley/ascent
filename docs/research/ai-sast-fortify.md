# Reference memo: fortify/skills

Clean-room reference note. Source: public GitHub page, README and repo metadata only, read 2026-10-06. No source code was cloned, read or copied. Everything below is paraphrase.

Repo: https://github.com/fortify/skills (OpenText Fortify).

## Licence and clean-room implication

**MIT** for the skills repository (GitHub licence metadata and README). The skills are prompt/instruction packs, so reuse risk is low. The important licence point is **not** the repo but what it drives: it is a front end for OpenText Fortify's **commercial** products (Fortify on Demand SaaS, Software Security Center on-prem) via the Fortify CLI (fcli). Those require a paid subscription or licence, and the analysis engines themselves are proprietary. This is a **commercial/licence trap for a free, Apache-2.0 tool**: Ascent cannot bundle or depend on it, and nothing in the repo performs SAST itself.

## What it is

Not a scanner. It is a bundle of agent "skills" (for Claude Code, Copilot, Gemini CLI, Codex and similar assistants) plus two orchestrating agents that let an AI assistant operate Fortify through fcli. Nine skills: FoD management, SSC management, vulnerability remediation, dependency upgrades, CVE exploitability analysis, code-change security review, app creation/onboarding, CI/CD integration, and general fcli use. Two agents: onboarding (single repo or whole portfolio) and exploitability analysis (batch over SBOM or Fortify vulnerability lists).

Invocation: the assistant selects a skill from the user's prompt; skills shell out to the locally installed fcli, which talks to the user's FoD tenant or SSC server.

## Architecture notes worth knowing

- **Exploitability / reachability triage:** the exploitability skill decides whether a known CVE or advisory in a dependency is actually reachable in this project, and emits per-CVE reports plus a combined **CycloneDX VEX** document. This is a useful output shape.
- **Change review:** a lightweight review of freshly generated or changed code for common high-impact issues.
- **Remediation:** AI-suggested fixes for already-found SAST/DAST findings, driven from Fortify's results.

## Data governance

- The README says code and vulnerability data stay local and nothing goes to external LLM services beyond what the user shares. Read that carefully: the "LLM" is the host coding assistant (Claude, Copilot, Gemini and so on), which is itself a hosted model, so any code or findings the skill puts into the conversation reach that provider. The statement is about Fortify not adding its own hop.
- Scans via FoD upload source or binaries to Fortify's **cloud**. SSC keeps it on-prem. Either way it requires a Fortify account.
- No local-model path is specified; it depends on whichever assistant hosts the skill.

## What Ascent should learn

1. **Reachability-based CVE triage as a distinct output**: pair trivy's dependency findings with a call-reachability judgement and emit **VEX** (CycloneDX). This fits Ascent's trivy stage and the human-review workflow, and can be done deterministically first (is the vulnerable symbol imported or called) with an LLM only for ambiguous cases.
2. **Skill-per-task decomposition** (triage, remediate, review change) as a model for how Ascent's later advisory layer might be split, each with narrow scope.
3. Per-finding, evidence-backed exploitability notes for the report.

## What to avoid

- Any dependency on Fortify FoD/SSC or fcli.
- Trusting the "stays local" claim without checking which model the host agent uses.
- Auto-remediation that edits code; Ascent stays human-in-the-loop and does not write to the target source.

## Subprocess or reimplement?

**Neither as a tool.** It cannot be invoked without a commercial Fortify backend. Reimplement only the ideas (reachability triage with VEX output).
