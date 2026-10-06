# Reference memo: DataDog/datadog-saist

Clean-room reference note. Source: public GitHub page, README and repo metadata only, read 2026-10-06. No source code was cloned, read or copied. Everything below is paraphrase.

Repo: https://github.com/DataDog/datadog-saist (the URL resolved; no fallback needed). Related but different project, noted only: https://github.com/DataDog/datadog-static-analyzer (deterministic, Apache-2.0 per GitHub metadata; not read in depth).

## Licence and clean-room implication

**Apache-2.0** (GitHub licence metadata and README statement; the raw LICENSE file was not separately opened, so treat as "confirmed by metadata"). Permissive and compatible with Ascent. No copyleft, no commercial trap in the code. One caveat: the tool fetches its detection rules from a Datadog-hosted public API by default; the rules' own licence terms were not verified, so Ascent must not ingest or redistribute them without checking.

## What it is and how it works

"SAIST" is an AI-native static analysis CLI (Go, preview status). It uses LLMs rather than pattern rules to find vulnerabilities.

- **Parsing:** Tree-sitter (Go bindings) builds syntax trees; the tool also builds a **project index** (skippable) that gives the model cross-file context about call and data relationships. The index can be disabled to save memory on big repos, at an accuracy cost.
- **Prompting:** prompts are generated from templates; user and system prompts can be dumped to files for debugging.
- **Two LLM phases:** a **detection** phase proposes issues using vulnerability-specific rules (the rule text acts as prompt content), then a **validation** phase, with an independently chosen model, filters false positives. Each phase's model is set separately on the command line.
- **Concurrency/timeouts:** per-file worker pool (default 20), per-request timeout (default 30 s).
- **Languages:** about 13 (Python, Java, JS, Go, C++, C#, Rust, PHP, Ruby, Kotlin, Swift, Elixir and others).
- **Output:** SARIF.
- **Invocation:** standalone CLI: target directory, output file, detection model, validation model.

## Data governance

- Supported providers: Anthropic, OpenAI, Google (hosted models, API keys in env vars). There is a custom OpenAI base-URL option, which means an OpenAI-compatible local server (Ollama, vLLM, llama.cpp server) is plausibly usable, but local models are **not documented or claimed as supported**; Ascent must not assume quality.
- So: **yes, it sends source to a hosted LLM by default**; there is no default-local path. Datadog says it does no hosting or processing of your code; code goes to whichever provider you pick. A separate Datadog "AI gateway" mode exists for routing/tracking.
- What is sent: file content plus index-derived cross-file context, plus the rule prompt. No redaction layer is described.
- Air-gap note: a flag uses detection rules embedded in the binary instead of fetching from the API, which removes the one non-LLM network call.

## What Ascent should learn

1. **Tree-sitter plus a lightweight project index** as the context-selection layer: rather than dumping whole files, hand the model only the function plus the callers/callees the index says matter. This is the core of cross-file source-to-sink reasoning and it also **shrinks what leaves the host or reaches the model**.
2. **Rule-as-prompt per vulnerability class**, kept as local data files that Ascent owns (author them clean-room; do not copy Datadog's fetched rules).
3. **Detect-then-validate with separately configurable models** (same lesson as the Rivian memo).
4. **SARIF as the exchange format**, which fits Ascent's normaliser-to-`Finding` design.
5. **Debug-prompt dumping** as an audit feature: write exactly what was sent to the model into the audit log. This is directly valuable for data-governance sign-off.
6. Offline-rules switch: the default must be "no network call except the model endpoint the operator approved".

## What to avoid

- Defaulting to hosted providers and a remote rule fetch.
- Trusting a custom base URL as "local support" without a quality benchmark on small local models.

## Subprocess or reimplement?

**Possible subprocess** (it is a clean CLI that emits SARIF) but a poor fit as a default: hosted-only by documentation, preview quality, and Go dependency. If an operator already pays for an approved provider, Ascent could optionally invoke it as an opt-in tool behind the same sign-off gate. For the MVP, **reimplement the index-based context selection and detect-then-validate pattern** inside Ascent.
