# LLM source-to-sink dataflow SAST (local-model): design

Status: direction approved by the author on 2026-10-06 ("base SAST on real AI-SAST projects"). This is the AI layer of Ascent's SAST track (PRD §3b: "LLM dataflow a la Vulnhuntr / Capital One VulnHunter"). It is a **follow-on** to the deterministic SAST stage (`docs/plans/2026-10-06-ascent-sast-track.md`), not a replacement. The technique is reimplemented clean-room from public AI-SAST projects (see `docs/research/ai-sast-*.md`); none of their code is used, and AGPL projects (Vulnhuntr, Buttercup) inform the *idea* only.

## Why it is separate from, and after, the deterministic stage

The deterministic analysers (opengrep/gitleaks/trivy) are fast, offline, and need no model. The LLM layer is slower, needs a model endpoint, and raises data-governance stakes (it reads source). Keeping it a distinct sub-stage lets a run use neither, either, or both, and keeps the model boundary in one auditable place.

## The make-or-break constraint: data governance

The surveyed hosted AI-SAST tools (rivian/ai-sast, DataDog SAIST, fortify) send source code to an external provider by default. **Ascent must not.** Per PRD §4/§7, source is sensitive and is routed to a **local model**; any non-local endpoint is an explicit, recorded exception.

- **Local by default.** The default model endpoint is a local Ollama (`http://127.0.0.1:11434`). A non-local endpoint is refused unless the engagement carries an explicit, recorded `llm_approved: true` plus the endpoint, and that approval is written to the audit log before any call.
- **The model endpoint is a scope target.** Every model call goes through the same `ToolRunner`/scope discipline: the endpoint host is checked, and a non-local host is out of scope unless approved as above.
- **Send slices, not files.** The LLM only ever sees small, bounded code slices around a candidate source/sink, never whole files or the whole repo.
- **Redact before sending.** Known secrets (from the gitleaks pass) are masked in any slice before it reaches the model.
- **Hard caps.** Byte caps per request, per file, and per run; a run that would exceed them stops rather than silently truncating.
- **Audit the prompts.** Each model call records a prompt hash (and an optional local-only full-prompt dump) in the hash-chained audit log, so "what was sent to which endpoint" is always answerable.
- **Code is untrusted input to the model.** Slices are wrapped so repository content cannot be read as instructions (prompt-injection hygiene); the model's output is parsed as data (strict JSON), never executed.
- **No remote rule fetch, no telemetry, no code execution, no auto-patching.**

## The technique (neurosymbolic, fail-closed)

Reimplements the IRIS/Metis pattern plus the VulnHunter falsification step:

1. **Deterministic context index (symbolic).** Build an index of the source with Tree-sitter (or reuse opengrep's parse) — functions, calls, parameters, and a set of candidate **sources** (request params, file reads, env) and **sinks** (query/exec/deserialize/path APIs). No model yet.
2. **Entry-point-forward tracing (symbolic).** From each source, walk the call graph toward sinks to assemble candidate source→sink **paths**, each a small bounded set of slices. This narrows what the model sees to the relevant few lines.
3. **Judgement (neural, bounded).** For each candidate path, the LLM judges only that path's slices: is this a real, reachable dataflow from untrusted source to dangerous sink, and what class (CWE)? Strict-JSON answer.
4. **Falsification (fail-closed).** A second pass asks the model to *disprove* each flagged path (find the sanitiser/guard that breaks it). A path survives only if it is flagged AND not falsified. **Unverified or ambiguous paths are ranked low and never marked confirmed** — the stage never inflates confidence.
5. **Emit `Finding`s.** Survivors become `category = "SAST"` findings (`file:line` at the sink, `cwe`, the source→sink summary as the message) and flow into Crux triage with the deterministic findings. Crux's abstain gate still routes low-confidence ones to a human.

## Components

- `src/sast_llm/index.rs` — the deterministic source/sink index and path builder (pure, heavily unit-tested; no model).
- `src/sast_llm/client.rs` — `trait LlmClient { fn complete(&self, prompt: &str) -> Result<String, ..>; }` with an `OllamaClient` (local HTTP) and a `MockLlmClient` for tests. The endpoint is scope-checked; non-local needs recorded approval.
- `src/sast_llm/judge.rs` — the judge + falsification prompts and strict-JSON parsing; redaction and byte caps applied here.
- `src/stages/sast.rs` (extended) — after the deterministic analysers, if a model is configured/approved, run the LLM dataflow sub-stage and append its findings.

## Testing

- The index/path builder on fixture source: finds the expected source→sink paths; produces bounded slices; no model involved.
- Redaction: a slice containing a known secret is masked before it reaches the `LlmClient` (assert via the mock).
- Byte caps: an over-cap run stops with a clear error, never a silent truncation.
- Judge/falsification with `MockLlmClient`: a flagged-and-not-falsified path becomes a confirmed finding; a flagged-but-falsified path is dropped or ranked low; malformed model JSON fails closed (no finding), never panics.
- Governance: a non-local endpoint without recorded approval is refused; the model host is passed through scope; a prompt hash is written to the audit log; the model's text output is never executed.
- Integration: with the LLM sub-stage off, the SAST stage behaves exactly as the deterministic MVP.

## Out of scope (later)

Multi-file whole-program taint beyond the call-graph slices; auto-fix/patch suggestions (the PRD keeps remediation advisory, human-applied); SAST-reachable + DAST-confirmed correlation (a later cross-track refinement); non-Ollama local backends (vLLM) — add behind the same `LlmClient` trait when needed.

## How it merges with the existing plans

It extends the SAST track plan as a clearly-separated sub-stage with its own implementation plan, gated behind a configured/approved local model. It changes nothing in triage/report/audit (still `Vec<Finding>`), and it is the concrete delivery of the PRD's "LLM dataflow" SAST item, done with the data-governance controls the hosted tools lack.
