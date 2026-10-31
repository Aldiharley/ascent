# Policy gate and SARIF — follow-ups

The policy gate (`--policy`, `ascent gate`), native SARIF 2.1.0 output and the exit-code contract (0 pass, 1 policy fail, 2 config error, 3 incomplete, 4 audit-chain failure) are done. The items below are deferred milestones from the gap analysis, plus issues found in review.

## Deferred milestones

1. **(M2) Finding state store and baselines.** Persist finding state keyed by the `ascent/v1` fingerprint with `first_seen`/`last_seen`. Emit SARIF `baselineState` as `new`/`unchanged`/`updated`/`absent`. Add a `not_rescanned` state that fails closed (a finding whose scanner did not run is never treated as fixed). Add `verified_fixed`, set only through the existing hash-bound re-test. Add `--baseline` and a `new_only` policy mode so a team can adopt the gate on a legacy codebase without failing on pre-existing findings.
2. **(M2) Waivers.** A waivers file where every entry has a mandatory `expires`, the proposer and approver must differ, and approval goes through the dashboard gate flow. Waiver events are chained into `audit.jsonl` and exported as SARIF `suppressions`. Grace periods are keyed on `first_seen`; an expired waiver never resets the grace clock.
3. **(M4) License findings.** `trivy --scanners license` mapped to a LICENSE category, with SPDX normalisation and policy deny/warn lists.
4. **(M4) Container images.** `trivy image` scans, scoped by a pinned digest or a registry allow-list so only images the engagement owns are scanned.

## DAST follow-ups

The DAST profiles, authenticated scanning (one static header) and the coverage matrix are done (see the README's DAST track section). Deferred:

1. **Scripted or form login and OAuth.** Authentication today is one static request header whose value comes from an environment variable, which covers bearer tokens and session cookies. Form-login automation, OAuth flows and token refresh are not supported.
2. **OpenAPI / GraphQL import.** The surface comes from the declared hosts and URLs plus a katana crawl. Importing an API description would let API endpoints that are not linked from a page be tested.
3. **Headless JS crawl.** katana runs without a headless browser. `-jc` extracts endpoints that appear literally in JavaScript files, but routes built at runtime in the browser are still missed.
4. **Verification allow-list cannot re-check fuzz findings.** The human-gated re-test is limited to `nuclei -id <id> -u <url> -silent -jsonl`. The command has no `-dast` flag and no way to carry fuzzing parameters, so findings from the `active` profile's `-dast` fuzzing pass cannot be re-checked through the current gate. Widening the allow-list is a deliberate safety decision and has not been made.
5. **Auth header value is visible in argv.** The value is passed to nuclei and katana as a `-H` argument, so other local users can read it from the process list while a scan runs. It is scrubbed from every output Ascent writes. A fix needs a way to hand the header to the scanners that keeps the value out of argv.

Deferred from the DAST final fix wave (2026-10-31):

6. **Per-host network errors from nuclei.** nuclei exits 0 when a host is unreachable (`no address found for host`), so a host that fails mid-scan looks like "no findings". The httpx probe catches dead declared URLs up front, but a host that dies during the scan is not detected. Fix: run nuclei with `-elog <file>` and treat `kind: network-permanent-error` entries per host as an incomplete scan.
7. **Hop-by-hop / reserved auth header names.** `dast.auth.header` accepts any valid header token, including `Host`, `Connection`, `Transfer-Encoding` or `Content-Length`, which would change request routing or framing rather than authenticate. Add a deny-list and reject them at load (exit 2).
8. **Secret scrub covers exact forms only.** The auth value is replaced in raw and JSON-escaped form. A scanner that echoes it URL-encoded, base64-encoded, truncated or case-changed would slip through. Consider scrubbing the common encodings too.
9. **`propose` uses `matched-at` as the re-check `-u`.** For templates whose path is relative to `{{BaseURL}}`, re-running against the matched URL can request a doubled path and report NOT_CONFIRMED for a real hit. Store the scanned input URL with the finding and re-check against that.

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
