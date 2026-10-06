# Reference memo: rivian/ai-sast

Clean-room reference note. Source: public GitHub page, README and LICENSE only, read 2026-10-06. No source code was cloned, read or copied. Everything below is paraphrase.

Repo: https://github.com/rivian/ai-sast

## Licence and clean-room implication

**Apache-2.0** (LICENSE file read; GitHub metadata agrees). Same licence as Ascent, so there is no copyleft or commercial trap. Even so, Ascent should not paste code: Apache-2.0 requires notices and change statements for derived files, and the useful parts here are design ideas, not code. Verdict: invoke or reimplement are both legally fine; reimplementing the few ideas below is simpler than depending on it.

## What it is and how it works

A GitHub-Actions-first "AI SAST" gate for pull requests. The flow is four steps: trigger (PR or manual dispatch), scan (an LLM reads code), optional validator (a second LLM re-checks each finding), results (PR comments plus HTML/text reports with CVSS vectors).

- **Analysis method: pure LLM.** There is no AST, call graph or dataflow engine described. Changed files (PR scan) or the whole repo (full scan) are batched and sent to the model. Languages: Python, JS/TS, Java, Go, Rust, C/C++.
- **Batching guardrails** (the most reusable idea): a default of about 10 files per request, a per-batch byte cap (about 2 MB), a per-file cap on added lines (about 500 KB) and a per-PR cap (about 5 MB), each disable-able. Purpose: avoid oversized requests and keep model quality steady.
- **Validator as FP control.** A second model classifies every finding as true or false positive and gives a short proof; only validated findings reach the PR. If the validator is unconfigured or errors, it fails open and posts everything.
- **Feedback loop.** Developers tick true/false-positive checkboxes in the PR comment; verdicts go to a local SQLite (or Databricks) store and are fed back into later prompts as context. Optionally, Jira tickets matching a JQL query are pulled in as history.
- **Custom prompt.** An env var appends organisation-specific instructions to the scan prompt.
- **Config files:** a workflow YAML, a gitleaks config (secrets scanning appears to be a companion piece), and an extensions allow-list for file types.
- **Invocation:** only through the GitHub Actions workflow. There is no standalone CLI or library API documented.

## Data governance (make-or-break)

- Supported scanner backends: Google Vertex AI (Gemini), AWS Bedrock (Claude), and **Ollama** (self-hosted; the README example uses a Qwen2.5-Coder 14B tag). Selection is by environment variable, with a separate selector for the validator model. The validator defaults to Bedrock.
- Therefore: **it is not local-only by default** (no safe default; you must pick a provider) and the validator defaults to a hosted model. A fully local run is possible by pointing both scanner and validator at an Ollama base URL.
- What is sent: raw source of changed files (full text of added lines and surrounding file content up to the caps), the custom prompt, and optionally feedback-database history and Jira ticket text. The project's own claim is that code never runs on the vendor's infrastructure and only snippets, not whole repos, cross the network. That is a statement about who hosts the runner, not about what the model provider sees. There is no redaction or secret-stripping step described before prompts are built.
- Risk to note: feeding Jira ticket text and prior findings into prompts widens what leaves the host.

## What Ascent should learn (reimplement clean-room)

1. **Size/volume guardrails** per request, per file and per run, with explicit "0 disables" semantics. Ascent should ship these on by default and make them part of the data-governance control (a hard ceiling on bytes that may reach any model).
2. **Separate scanner and validator model roles**, individually configurable (e.g. local model for both, or local scanner plus an approved remote validator only with sign-off).
3. **Validator-gates-output** design, but Ascent should fail CLOSED (unvalidated means not reported as confirmed, or reported as "unverified"), the opposite of this tool's fail-open fallback.
4. **Human feedback loop** into later runs, which maps neatly onto Ascent's human-in-the-loop gates and audit log. Store verdicts in Ascent's own audit store, not a cloud warehouse.
5. Provider abstraction by one config key with `ollama` as a first-class option.

## What to avoid

- Fail-open validator fallback.
- No redaction layer before prompts.
- Pure-LLM scanning with no deterministic anchor, so no reproducible evidence and no reachability reasoning.
- Pulling third-party ticket systems into prompts by default.
- CI-only invocation (Ascent needs a local, scope-enforced CLI path).

## Subprocess or reimplement?

Not a good subprocess candidate: it is a GitHub Actions workflow, not a CLI, and it hard-wires PR-comment output. **Reimplement the ideas** (batch caps, scanner/validator split, fail-closed validation, feedback store).
