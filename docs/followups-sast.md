# SAST track — follow-ups

From the final whole-branch review of `feat/sast-track` (the track is merge-ready; all safety non-negotiables hold). None blocks the MVP.

1. **Verify the real analyser flags and JSON.** The unit tests use fake runners; opengrep/gitleaks/trivy are not installed on the dev machine, so the exact CLI flags and output shapes are unverified against live tools. Install them and do a smoke run against a known-vulnerable source tree; adjust the stage's arg lists if a tool's real output differs (keep the normaliser contracts and the secret-redaction guarantee). In particular confirm gitleaks accepts `--report-path -` for stdout on Windows.
2. **Air-gapped / governed analyser posture.** The analyser subprocesses make their own outbound calls: `opengrep --config auto` fetches rules from the registry; `trivy fs` updates its vuln DB. For a fully offline run, pin a local opengrep ruleset and pass `trivy --skip-db-update --offline-scan` (needs a pre-cached DB). opengrep telemetry is already off (`--metrics=off`). This is the model the data-governance spine expects.
3. **Opengrep secret-classification heuristic.** `secret_rule` (in `src/normalise.rs`) blanks `evidence`+`message` when a rule carries CWE-798/259/321/312 or a secret-ish id keyword. A hardcoded-secret rule carrying none of those would keep its source line. Standard opengrep secrets rules carry those CWEs, so no leak in practice; add a code comment, and consider always blanking evidence for any rule under a "secrets" ruleset path.
4. **Unbounded tool output.** `ToolRunner` reads a subprocess's whole stdout into memory (pre-existing pipeline pattern). opengrep/trivy over a very large tree could be large. Consider a size cap if it becomes a problem.
5. **Cosmetic (pre-existing).** The CLI prints the `audit.jsonl` path even on a no-findings run where the file isn't written; `main` prints errors Debug-quoted (`Error: "..."`). Both are minor UX.

See also the LLM-dataflow SAST design (`docs/superpowers/specs/2026-10-06-llm-dataflow-sast-design.md`) for the governed, local-model AI layer that builds on this deterministic track.
