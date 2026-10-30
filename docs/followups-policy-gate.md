# Policy gate and SARIF — follow-ups

The policy gate (`--policy`, `ascent gate`), native SARIF 2.1.0 output and the exit-code contract (0 pass, 1 policy fail, 2 config error, 3 incomplete, 4 audit-chain failure) are done. The items below are deferred milestones from the gap analysis, plus issues found in review.

## Deferred milestones

1. **(M2) Finding state store and baselines.** Persist finding state keyed by the `ascent/v1` fingerprint with `first_seen`/`last_seen`. Emit SARIF `baselineState` as `new`/`unchanged`/`updated`/`absent`. Add a `not_rescanned` state that fails closed (a finding whose scanner did not run is never treated as fixed). Add `verified_fixed`, set only through the existing hash-bound re-test. Add `--baseline` and a `new_only` policy mode so a team can adopt the gate on a legacy codebase without failing on pre-existing findings.
2. **(M2) Waivers.** A waivers file where every entry has a mandatory `expires`, the proposer and approver must differ, and approval goes through the dashboard gate flow. Waiver events are chained into `audit.jsonl` and exported as SARIF `suppressions`. Grace periods are keyed on `first_seen`; an expired waiver never resets the grace clock.
3. **(M4) License findings.** `trivy --scanners license` mapped to a LICENSE category, with SPDX normalisation and policy deny/warn lists.
4. **(M4) Container images.** `trivy image` scans, scoped by a pinned digest or a registry allow-list so only images the engagement owns are scanned.

## Verify early

- opengrep exit codes were verified on 2026-10-30: 0 with findings, 2 on error. Re-check on tool upgrades, since the gate treats a failed scanner as INCOMPLETE.
- Fingerprint robustness against real refactors (moved files, renamed functions, reformatting). The fingerprint has no line numbers by design; measure how often it still splits or merges findings across a real diff.
- GitHub `security-severity` band edges: confirm the numeric score thresholds that map to Critical/High/Medium/Low in code scanning match the values Ascent emits.

## Issues found in review

- **A policy with no `fail_on` severity or CWE can never fail.** Consider warning (or refusing) at load time so an empty `fail_on` is not mistaken for a working gate.
- **`normalise_url` keeps unparseable or relative URLs verbatim.** Two spellings of the same unparseable URL fingerprint differently. Decide whether to reject, resolve against a base, or accept this and document it.
- **Finding `id`s still embed the absolute source path.** The SAST normalisers build `id` (e.g. `opengrep:<rule>:<abs path>:<line>`) before the pipeline makes `file` source-relative, so queue.json and the audit log's triage entries show local paths such as the user's home directory. Fingerprints are unaffected (they use `file`). Found in live validation on 2026-10-30. Fix: build ids from the relativised path, or relativise before normalising.
- **Smaller items from the per-task reviews:** sort-independent `cwe_first` (a rule tagged `[CWE-20, CWE-89]` only matches its first CWE); one shared "credential finding" predicate for the opengrep normaliser and `fingerprint::kind` (CWE-312 / keyword rules currently fingerprint on line number); the dashboard `getGate` should type-check each entry field and key list items by index; DAST `locus` and SARIF URIs keep query values (consider stripping them as the fingerprint does).

## Non-goals

Auto fix PRs, AI-generated patches, an IDE plugin, and malware scanning.
