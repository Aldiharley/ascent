# AI-SAST research synthesis and recommendation for Ascent's SAST track

Clean-room research, public READMEs, licence files and GitHub metadata only, read 2026-10-06. No source cloned or copied. Individual memos:

- [ai-sast-rivian.md](ai-sast-rivian.md)
- [ai-sast-datadog.md](ai-sast-datadog.md)
- [ai-sast-fortify.md](ai-sast-fortify.md)
- [ai-sast-awesome-list.md](ai-sast-awesome-list.md) (also covers Vulnhuntr, VulnHunter, IRIS, Metis, nano-analyzer and others)

All four target URLs were reachable; none had to be substituted.

## Licence and data-governance table

| Project | Licence | Clean-room implication | Sends source to external LLM by default? | Local model (Ollama/self-hosted)? | Usable as Ascent subprocess? |
|---|---|---|---|---|---|
| rivian/ai-sast | Apache-2.0 | Safe to learn from or reuse with notices; ideas are small, reimplement | No safe default: you must choose Vertex or Bedrock; validator defaults to Bedrock. Raw source of changed files goes to the chosen provider; no redaction | Yes (Ollama for scanner and validator) | No (GitHub Actions workflow only) |
| DataDog/datadog-saist | Apache-2.0 (rules fetched from a Datadog API; their terms unverified) | Safe; do not ingest Datadog's rules | Yes: hosted Anthropic/OpenAI/Google only documented; file text plus index context sent | Not documented; custom OpenAI-compatible base URL might work | Yes technically (CLI, SARIF), hosted-only so opt-in at best |
| fortify/skills | MIT (repo); drives commercial Fortify FoD/SSC | Commercial licence trap for the backend; skills alone do nothing | Depends on the host AI assistant (hosted); FoD uploads source to Fortify cloud | No | No (needs paid Fortify) |
| awesome-ai-security-tools | CC0-1.0 (list); entries vary | Mining is free; check every entry | Mostly yes (hosted-first ecosystem) | Few: Metis, IRIS, Clearwing (partly) | Metis maybe; others no |
| Vulnhuntr (Protect AI) | AGPL-3.0 | Copyleft: idea only, never copy or port | Yes (Claude/GPT default) | Experimental Ollama | No |
| VulnHunter (Capital One) | Apache-2.0 | Learn technique; Claude-Code-bound | Yes (Anthropic) | No | No |
| IRIS | MIT | Pattern is reusable; CodeQL-bound research code | Choice of hosted or local | Yes | No |
| Metis (Arm) | Apache-2.0 | Safe | Choice; local supported first-class | Yes (Ollama, vLLM) | Possible, opt-in |
| nano-analyzer | Apache-2.0 | Safe, tiny | Yes (OpenAI/OpenRouter) | Not documented | No |

## Findings

1. **Almost nobody is local-first.** The field defaults to hosted models and treats redaction as the user's problem. Ascent's local-model-by-default stance is a real differentiator, not table stakes.
2. **No project does reliable LLM dataflow with small local models.** Vulnhuntr's own authors say open models struggle with structured output; Capital One's tool explicitly needs a frontier model. Ascent must design for weak local models: small, tightly bounded prompts, strict JSON schemas with retry, and heavy deterministic pre-work.
3. **The strongest pattern is neurosymbolic**: let deterministic tools do what they are exact at (parsing, call graphs, taint rules, opengrep matches) and let the LLM do only the judgement steps (is this a source, does this sanitiser neutralise the sink, is the finding real). IRIS (LLM infers sources/sinks, engine runs the dataflow) and Metis (SARIF in, evidence-based triage out) both do this and both work with local models.
4. **Every credible tool has an adversarial second pass** (Rivian validator, Datadog validation phase, VulnHunter falsification, nano-analyzer skeptical triage). That is the false-positive control to copy.
5. **Nondeterminism is real**: Cloudflare reports a single agentic run catches only about half of what repeated runs catch. Ascent should record model, prompt hash and seed settings, and label LLM findings as "model-assessed", never as proven.
6. **Licence traps**: Vulnhuntr and Buttercup (AGPL), nuclei-autotriage (non-commercial EULA), Fortify's backend (commercial), Trail of Bits skills (share-alike). Nothing else is a problem.

## Recommendation

**(a) plus (c): keep the deterministic opengrep/gitleaks/trivy stage as the MVP and add an LLM source-to-sink sub-stage that talks to a LOCAL model by default, reimplemented clean-room. Do not adopt any of these projects as a required subprocess.** Optionally allow Metis or datadog-saist as opt-in, sign-off-gated external tools later; they are not needed.

Why not (b): the only tools that are CLI-invokable and Apache are either hosted-only (datadog-saist), CI-only (Rivian), or aimed at a narrower job (Metis, C/C++ reachability). None gives Ascent scope enforcement or audit of what went to a model, which are Ascent's own value. A subprocess would also put a second, uncontrolled network client next to the scope boundary.

### Technique to reimplement (single most useful)

**Entry-point-forward source-to-sink tracing with a falsification pass, over a deterministic context index.** In order:

1. Deterministic candidates: opengrep hits and a tree-sitter symbol index give sinks and entry points; the LLM is not asked to find the whole codebase's bugs, only to judge bounded slices.
2. Context assembly: for each candidate, build a small slice (sink function plus callers up the call chain, bounded by a token budget). This is Vulnhuntr/Datadog's "ask for the next function" loop, but driven by the index rather than by the model asking for files, so the model never sees more than the slice.
3. Dataflow judgement prompt: given a slice, answer in strict JSON: source reachable from external input? sanitiser/validator on the path? sink exploitable? confidence 0 to 1, with the lines relied on.
4. Falsification pass: a second prompt (same or different local model) tries to disprove the finding (guards, framework protections, dead code). Fail closed: a finding that cannot be validated is reported as "unverified" and ranked low, never as confirmed.
5. Output: normal `Finding`s with `category = "SAST"`, an `llm_assessed` marker, evidence lines, and the prompt hash, entering the existing triage unchanged.

Also borrow: per-request/per-file/per-run byte caps on by default (Rivian), prompt dumps into the audit log (Datadog), a confidence floor (nano-analyzer), reachability-based CVE triage with CycloneDX VEX output for trivy results (Fortify's exploitability idea; do this deterministically first).

### Data-governance controls Ascent needs

- **Local by default.** The LLM sub-stage is disabled unless a model endpoint is configured; the default provider kind is a local Ollama-compatible endpoint, which must resolve to loopback (or an engagement-declared allow-listed internal host).
- **Egress is a scope decision.** A model endpoint is treated like a network target: it must appear in the engagement file, be checked by the same scope guard, and any non-local endpoint requires an explicit per-engagement `source_egress_approved` field recorded with approver and time. Without it the stage refuses to start. No env-var override.
- **Redaction before any prompt**, even local, because logs and caches persist: strip secrets using gitleaks' rule hits (reuse the rule id and location, never the value), mask high-entropy strings and known credential patterns, drop comments that match secret-like or PII patterns optionally, and replace absolute paths with relative ones. For a remote model additionally hash identifiers (optional) and send only slices, never whole files.
- **Hard caps**: maximum bytes per request, per file, per run, and a maximum total bytes allowed to leave the host; exceeding aborts and is audited.
- **No source leaves the host otherwise**: no remote rule fetch, no telemetry, no model-provider "gateway", no ticketing integration in prompts.
- **Audit**: log (not the code itself) the endpoint, model name and digest, the prompt template version, a hash of each prompt, byte counts, and the redaction counts; optionally write full prompts to a local, access-controlled debug directory when the operator enables it.
- **Prompt-injection hygiene**: code is untrusted data. Wrap it in delimiters, instruct the model to ignore instructions in it, validate output against a JSON schema, and never let model output choose commands, paths or tools. The LLM sub-stage is read-only and cannot execute anything.
- **Human gate**: LLM-assessed findings are advisory and require analyst approval before any exploitation stage (the Phase 5 design) can use them.

### Integration point in `docs/plans/2026-10-06-ascent-sast-track.md`

Keep Tasks 1 to 5 as written (the MVP: source root, opengrep/gitleaks/trivy normalisers, `sast()` stage, pipeline merge, CLI `--source`). Add a **follow-on Task 6 (a separate plan)** that:

- adds a `sast_llm` stage in `src/stages/` called from Task 4's pipeline step immediately after `sast()` returns its `Vec<Finding>` and before the SAST+DAST merge and triage;
- takes the opengrep findings plus the source root (still gated by `is_within`) as inputs, so the LLM only judges candidates the deterministic tools already surfaced (this keeps volume and exposure small), with an optional later "entry-point sweep" mode;
- defines an `LlmClient` trait (mockable like `Runner`/`MockTriager`) with a local Ollama HTTP implementation and a `MockLlm` for tests, so the stage is testable without a model;
- relaxes the plan's current Global Constraint "no external LLM in this plan" only for this new plan, replacing it with the controls above; the MVP plan itself stays offline and unchanged.

Open items to validate before building: which local model sizes give acceptable strict-JSON adherence (benchmark on OWASP Juice Shop, which the repo already uses as a lab), and token budgeting per slice.

### What not to do

No autonomous exploit generation or code execution in this stage, no auto-patching of the target, no fail-open validation, no vendoring or porting from AGPL projects, and no dependency on Fortify or any hosted-only service.
