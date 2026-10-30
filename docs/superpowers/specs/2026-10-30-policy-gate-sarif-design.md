# Policy gate, CI exit codes and native SARIF — design

Date: 2026-10-30
Status: approved for build (autonomous, per the gap-analysis request)
Source: `docs/research/2026-10-30-veracode-gap-analysis.md` (Milestones 1 and 3)

## Problem

Ascent scans, triages and audits well, but it never gives a **verdict**. A
successful `ascent run` always exits 0, so it cannot gate a CI pipeline, and its
results never reach GitHub code scanning or an IDE. The gap analysis against
Veracode ranks these as the two Critical gaps (policy evaluation, CI exit-code
gating) plus a High gap (SARIF). Veracode's real gate is a policy verdict —
Passed / Conditional Pass / Did Not Pass — and the SecAI page's own policy and
CLI examples are not valid Veracode syntax, so this design follows Veracode's
documented semantics and open standards, not that page.

## Goals

1. A versioned YAML **policy** evaluated over the triaged findings, producing
   `PASS`, `CONDITIONAL` or `FAIL`, written to `out/gate.json` and chained into
   `audit.jsonl`.
2. A documented **exit-code contract** so only Ascent's policy decides the CI
   result, and every failure mode fails closed.
3. An **incomplete-scan** signal: if a scanner errored or the run was a dry run,
   the gate cannot pass.
4. A stable, versioned **finding fingerprint** (`ascent/v1`) that does not
   depend on line numbers, used by the gate and SARIF now and by baselines later.
5. **Native SARIF 2.1.0** output (`out/ascent.sarif` for code findings,
   `out/ascent-dast.sarif` for URL findings) that `github/codeql-action/upload-sarif`
   accepts.
6. SCA findings carry the **installed and minimal fixed version** (today the
   trivy normaliser drops them).
7. The dashboard shows the gate verdict **read-only** on the Overview, in the
   existing Fluid Glass style. The dashboard never launches runs.

## Non-goals (this build)

- Baselines / new-fixed-persisting delta, finding state store, waivers, grace
  periods (gap-analysis Milestone 2). The policy schema rejects these keys for
  now (`deny_unknown_fields`), so they can be added later without a silent
  behaviour change.
- License and container-image scanning (Milestone 4).
- Automatic fix PRs and AI patches (deliberate non-goals for a human-in-the-loop tool).
- `primaryLocationLineHash` computation: `upload-sarif` computes it from the
  checkout when absent; Ascent emits its own `ascentFindingHash/v1`.

## Exit-code contract

| Code | Meaning |
|---|---|
| 0 | Run succeeded; policy PASS or CONDITIONAL (or no `--policy` given) |
| 1 | Policy FAIL (or CONDITIONAL with `--fail-on-warn`) |
| 2 | Usage / config error: unreadable engagement, malformed or unknown-key policy |
| 3 | Incomplete: a scanner or pipeline stage failed, the run was a dry run, or `run.json` is missing — the gate refuses to pass |
| 4 | Integrity failure: the audit hash chain does not verify |

Without `--policy`, `ascent run` keeps today's behaviour on success (exit 0);
runtime errors now exit 3 instead of the generic 1, so 1 always means "policy
failed". This is a deliberate, documented change.

## Policy schema (`version: 1`)

```yaml
version: 1
name: default
fail_on:
  severity: [CRITICAL, HIGH]
  categories: [SAST, SCA, SECRETS, DAST]   # default: all four
  cwe: []                                   # e.g. [CWE-89, CWE-798]
warn_on:
  severity: [MEDIUM]
  cwe: []
triage:
  likely_false_positive: demote_to_warn     # demote_to_warn (default) | enforce
```

Rules:
- Unknown keys anywhere → exit 2 (fail closed on typos and on future keys).
- `version` must be `1`. Severities must be one of CRITICAL/HIGH/MEDIUM/LOW/INFO.
  Categories must be one of SAST/SCA/SECRETS/DAST. CWE entries must match `CWE-<digits>`.
- A finding's category is `SECRETS` when its tool is gitleaks, else its own category.
- Per finding, in order: category filter → `fail_on` match (severity or CWE) →
  `warn_on` match. A `fail_on` match whose verdict is `LIKELY_FALSE_POSITIVE`
  is **demoted to a warning**, never silently passed (an offline triager must
  not clear a gate on its own; only a future human-approved waiver may).
  With `enforce`, it fails like any other.
- Decision: incomplete run → `INCOMPLETE` (exit 3); any failure → `FAIL` (1);
  else any warning → `CONDITIONAL` (0, or 1 with `--fail-on-warn`); else `PASS` (0).
- `policy_hash` = SHA-256 of the canonical JSON of the parsed policy, so the
  audit entry proves which policy decided.

## Fingerprint `ascent/v1`

`sha256("ascent/v1" ‖ kind ‖ inputs…)`, rendered `ascent/v1:<hex>`.

| Kind (from tool) | Inputs | Excluded |
|---|---|---|
| sast (opengrep / other file findings) | rule_id, normalised path, sha256 of the evidence with all whitespace removed (falls back to the line number only when evidence is empty), occurrence index | line number |
| secret (gitleaks) | rule_id, normalised path, occurrence index | line, any secret value or hash of it |
| sca (trivy) | rule_id (CVE), normalised target path, package name | installed version |
| dast (nuclei / any URL finding) | rule_id, normalised URL: lowercase scheme+host, explicit port only if non-default, path with numeric / UUID / long-hex segments replaced by `{}`, sorted query *names*, no values, no fragment | query values |

Path normalisation: backslashes → `/`, strip a leading `./`, strip the source
root prefix when known. The occurrence index disambiguates identical
fingerprints within one run, in input order.

Deviation from the research recommendation: secrets do **not** hash the secret
value. Ascent stores no secret-derived data anywhere; the cost is that a rotated
secret in the same file and rule is not distinguished from the old one.

## Run status (`out/run.json`)

Written by every `ascent run`: `{ "complete": bool, "dry_run": bool,
"failed_tools": [..], "finished_at": ts }`. `complete` is false when any SAST
tool errored (today it is silently skipped) or in dry-run. A DAST/recon error
already aborts the run (exit 3). `ascent gate` treats a missing or unparseable
`run.json` as incomplete.

## Gate output (`out/gate.json`)

```json
{ "policy": {"name": "default", "hash": "<sha256>"},
  "decision": "FAIL", "exit_code": 1, "complete": true,
  "counts": {"evaluated": 12, "failed": 2, "warned": 3, "demoted_fp": 1},
  "failed": [{"fingerprint": "ascent/v1:…", "rule_id": "…", "severity": "HIGH",
              "category": "SAST", "title": "…", "locus": "src/db.rs:42",
              "reason": "severity HIGH in fail_on"}],
  "warned": [ … same shape … ],
  "evaluated_at": "<ts>" }
```

After writing, Ascent verifies the audit chain (broken → exit 4) and appends a
`gate_evaluation` entry `{decision, exit_code, policy_hash, gate_hash}` via the
existing `append_chained`, so the verdict is tamper-evident.

## CLI

- `ascent run … [--policy FILE] [--fail-on-warn]` — runs, writes `run.json`,
  SARIF, and (with `--policy`) evaluates the gate; exits per the contract.
- `ascent gate --policy FILE [--out DIR] [--fail-on-warn]` — evaluates an
  existing output dir (CI step after a run).
- `ascent sarif [--out DIR] [--source-root DIR]` — regenerates the SARIF files
  from `queue.json`.

## SARIF mapping

One run per category (`automationDetails.id` = `ascent/sast/`, `ascent/sca/`,
`ascent/secrets/`) in `ascent.sarif`; DAST in `ascent-dast.sarif`
(`ascent/dast/`), because GitHub cannot fingerprint `https://` URIs.
`tool.driver.name = "Ascent"`, `rules[]` de-duplicated by rule_id with
`shortDescription`, `properties.tags = ["security", CWE…]` and
`security-severity`.

| Severity | level | security-severity |
|---|---|---|
| CRITICAL | error | 9.5 |
| HIGH | error | 8.0 |
| MEDIUM | warning | 5.5 |
| LOW | note | 2.0 |
| INFO | note | (omitted) |

Results: `ruleId`, `level`, `message.text`, `locations[].physicalLocation`
(`artifactLocation.uri` relative, `region.startLine` ≥ 1) or for DAST an absolute
`artifactLocation.uri`, `partialFingerprints["ascentFindingHash/v1"]`,
`properties["ascent.tool" | "ascent.verdict" | "ascent.confidence" |
"ascent.remediation"]`. A `LIKELY_FALSE_POSITIVE` result carries
`suppressions: [{kind: "external", status: "underReview", justification}]`.
Secrets: message text only, never a value (already redacted upstream).

## Dashboard

- `GET /api/gate` → contents of `out/gate.json`, or `null` when absent. Read-only.
- Overview gains a **Policy gate** card at the top of the main column: a verdict
  pill (PASS green / CONDITIONAL amber / FAIL red / INCOMPLETE grey), policy name
  and short hash, the counts, the first five failing findings, and the CI exit
  code. With no gate.json it shows how to enable one (`--policy`). All strings
  rendered as React text only. Same glass tokens; no new image assets needed
  (inline SVG icons), so no generated assets.

## Testing

- Unit: fingerprint stability (line shift, whitespace, query values, version
  bumps don't change it; rule/path/package changes do), policy parse + every
  rejection path, evaluator decision table incl. demotion and incomplete,
  SARIF shape (required fields, level mapping, suppressions, DAST split,
  relative URIs), trivy enrichment.
- Integration: `run --policy` and `gate` exit codes 0/1/2/3/4 via the binary
  (`std::process::Command` on `CARGO_BIN_EXE_ascent`) on fixture out dirs.
- Frontend: PolicyGate renders each decision and the empty state.
- Live: dry-run → exit 3; fixture queue → FAIL → exit 1; dashboard shows the card.
