# Reference memo: Shannon (KeygraphHQ)

Clean-room reference note. Source: public GitHub page, README and LICENSE only, read 2026-10-06. No source code was cloned, read or copied. Everything below is paraphrase.

Repo: https://github.com/KeygraphHQ/shannon

## Purpose and licence

An AI "pentester" for web applications and APIs that combines source-code analysis with live exploitation, with the stated goal of proving vulnerabilities before release. It reports only what it could demonstrate against the running app.

**Licence: AGPL-3.0** for the open-source edition (confirmed from the repo's LICENSE file). The vendor also sells separate commercial/enterprise licensing.

Implication for Ascent: AGPL-3.0 copyleft applies to any copy, port or translation of its source, including a Rust rewrite; the derivative stays bound by AGPL, and a public repo does not change this. The existence of a commercial licence also shows the vendor treats the code as protected. Ascent may learn the ideas and reimplement independently under Apache-2.0.

## Architecture and orchestration patterns

- **Five-phase pipeline.** (1) Reconnaissance against the running app with specialised investigations per class (injection, XSS, SSRF, authentication, authorisation); (2) code analysis mapping architecture, trust boundaries, interfaces, data flows and critical assets; (3) reconciliation that merges candidates from both streams, removes duplicates and prioritises; (4) exploitation agents that attempt proof-of-concept attacks; (5) reporting.
- **White-box plus black-box fusion.** Static understanding of the code guides what to probe live, and runtime behaviour is tied back to code.
- **Proof-gated findings.** Only hypotheses confirmed against the live app become findings or count toward release gates; unconfirmed ones are discarded. This reduces false positives.
- **Per-class parallel specialists** feeding a shared candidate queue.
- **Ephemeral containers.** Each run gets an isolated workspace in a throwaway Docker container, with read-only access to the target repository.
- **Resumable workflows.** Interrupted runs continue without redoing completed analysis (durable workflow state).
- **Config-driven engagement.** Files describe authenticated testing (login flows, TOTP, email-based auth), rules of engagement and report filtering.
- **Outputs and CI.** PDF, Markdown, JSON and SARIF 2.1.0; GitHub Actions and GitLab CI integrations can gate releases on proven findings.
- **Stated limits.** Scans take roughly one to one and a half hours and cost model tokens; untrusted code can attempt prompt injection against the analysis layer; human review of LLM output is still required. Results stay local and model traffic is not proxied through the vendor.

## Mapping to Ascent's stance

Deliberately EXCLUDED (studied only to define the exclusion):
- Autonomous exploitation agents that run real proof-of-concept attacks, mutate application state, create users and submit forms without a human deciding each step.
- A model being the sole driver of an engagement; Ascent keeps a human approval gate on any intrusive or state-changing action.
- The "exploit to confirm" model as default. Ascent's confirmation must use non-destructive, scope-checked, human-approved verification.

Safe to reimplement clean-room:
- Phase structure with an explicit reconciliation step that merges and deduplicates candidates from several sources, then queues them for human triage.
- Treating static (code, config, dependency) analysis and dynamic observation as complementary evidence streams.
- An evidence-gated finding model: a candidate is not "confirmed" until supporting evidence is attached and a human accepts it.
- Ephemeral, isolated workspaces per run and read-only mounting of the target source.
- Checkpointed, resumable runs.
- Engagement configuration files for scope, rules of engagement, auth context and report filtering; SARIF 2.1.0 output and CI gating on confirmed findings.
- Prompt-injection hygiene when feeding untrusted code or pages to a model (treat as data, never instructions).

## Clean-room boundary

May reimplement under Apache-2.0 from our own design:
- Reconcile-and-dedupe stage; evidence-gated confirmation with human sign-off; ephemeral per-run sandboxes; resumable run state; engagement config schema of our own design; SARIF/Markdown/JSON reports; CI gate on confirmed findings.

Must never be copied or ported:
- Their source in any language, prompts, agent definitions, workflow definitions, config schema text, Docker setup, report templates, documentation prose or branding. Do not reproduce their exploitation playbooks (excluded by policy).
- Do not keep the repo open as a model while implementing; design from Ascent's own docs.

## Access notes

GitHub page, raw README and raw LICENSE fetched successfully. Source files were not read.
