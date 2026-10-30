# Ascent

Ascent is an open-source (Apache-2.0), scope-enforced, human-in-the-loop AppSec pipeline written in Rust. It drives external open-source scanners as subprocesses (opengrep, gitleaks and trivy for source code; nuclei with httpx and katana for running web targets), triages the findings with the offline [Crux](https://github.com/Aldiharley/crux) engine, and produces a ranked report, a hash-chained audit log and native SARIF 2.1.0. A YAML policy turns the result into a CI-friendly verdict. Every network target passes a fail-closed scope guard, and nothing is ever exploited automatically: a human approves each detect-only verification step in a local dashboard.

![Ascent dashboard overview: policy gate verdict, KPI tiles, triaged findings, a pending approval gate and the hash-chained audit log](docs/images/dashboard-overview.png)

*The Overview screen over a demo lab dataset: the policy gate verdict (FAIL, exit code 1) with the top failing findings, the findings table, a pending detect-only approval gate, and the audit log with its "Hash chain OK" check.*

Use Ascent only against systems you own or have explicit written permission to test.

## How it works

1. **Scope.** An engagement file lists the hosts, CIDRs and URLs you are authorised to test (and optionally a source directory). Every target is checked against it before any network request; an ambiguous or out-of-scope target is refused.
2. **Scan.** Ascent invokes the external scanners as subprocesses: opengrep (SAST), gitleaks (secrets) and trivy (SCA) over source, and nuclei (with httpx/katana) over in-scope web targets.
3. **Triage.** The offline Crux engine labels each finding TRUE_POSITIVE, NEEDS HUMAN or LIKELY NOISE, with a confidence.
4. **Policy gate.** A YAML policy yields PASS, CONDITIONAL, FAIL or INCOMPLETE, with an exit code for CI. A crashed or missing scanner never passes.
5. **Human-approved verification.** For confirmed-looking DAST findings Ascent can propose a detect-only re-check. It runs only after a person approves it in the dashboard.
6. **Report, SARIF and audit log.** The run writes `report.md`, `ascent.sarif` / `ascent-dast.sarif`, and `audit.jsonl`, a hash-chained log in which any tampering is detectable.

## Quick start

Prerequisites: a Rust toolchain, Node.js and npm. Crux is a path dependency, so check it out next to Ascent (see [Building](#building)).

1. **Build.**

   ```
   cargo build
   cd frontend && npm ci && npm run build && cd ..
   ```

2. **Start the dashboard** from the repo root, and open <http://127.0.0.1:8787>:

   ```
   cargo run --bin dashboard
   ```

   It is fine for it to be empty before the first run. It reads results from `out/` (`ASCENT_OUT` changes that).

3. **Define a scan.** Open New Scan, enter the targets you are authorised to test (for example `localhost`, `127.0.0.0/8` and `http://localhost:3000/`) and optionally a source directory for SAST. Pick a DAST profile (passive, standard or active; the default is standard, and `active` adds parameter fuzzing, so use it only on targets you may actively test). For an authenticated scan you can also give an auth header name and the name of the environment variable that holds its value (never the value itself); see [DAST track](#dast-track). Ascent validates the input and writes an engagement scope file under `engagements/`. This screen only defines scope and settings; it never launches a scan. It shows the exact command to run:

   | Scope defined, with the command to copy | Ambiguous targets refused, nothing written |
   |---|---|
   | ![New Scan screen with a scope entered and the Scan defined card showing the ascent run command](docs/images/dashboard-new-scan.png) | ![New Scan screen refusing evil.example/path and "exa mple.com" because they are not valid, unambiguous entries](docs/images/dashboard-new-scan-rejected.png) |

4. **Run it from the terminal**, with the policy gate. The engagement path is the one the New Scan screen printed (`ascent run` is the installed CLI; from a checkout use `cargo run -- run`, or install it with `cargo install --path .`):

   ```
   cargo run -- run --engagement engagements/<name>.yaml --out out --policy samples/ascent-policy.example.yaml
   ```

   The process exit code follows the verdict (see [Policy gate and CI](#policy-gate-and-ci)). With DAST scope the run also prints a `dast:` line (profile, authenticated or not, and how many URLs were seeded, crawled, dropped as out of scope and scanned) and the path of `dast-coverage.json`.

5. **Review in the dashboard.** Refresh <http://127.0.0.1:8787> to see the policy verdict, the triaged findings, the report and the audit log.

Scanners are external and optional per track. Ascent does not bundle them; install the ones you want on your `PATH`.

- **SAST track** (source directory): [opengrep](https://github.com/opengrep/opengrep), [gitleaks](https://github.com/gitleaks/gitleaks) and [trivy](https://github.com/aquasecurity/trivy). A scanner that is not installed is skipped, but a policy that needs its category then ends INCOMPLETE (exit 3).
- **DAST track** (hosts or URLs): [nuclei](https://github.com/projectdiscovery/nuclei) plus ProjectDiscovery [httpx](https://github.com/projectdiscovery/httpx) (and subfinder/katana for recon). On Windows, a pip-installed Python `httpx` can shadow ProjectDiscovery httpx on `PATH`; make sure the ProjectDiscovery binary is the one found first.

To try it without a lab target, use the sample engagement directly: `cargo run -- run --engagement samples/engagement.example.yaml --out out --policy samples/ascent-policy.example.yaml`. It targets the local machine only.

## Safety model

- **Authorised targets only.** Scope is declared up front in the engagement file and every network target is checked against it, fail closed.
- **Nothing exploits automatically.** The only thing Ascent ever runs against a target after triage is an allow-listed, detect-only `nuclei -id <id> -u <url> -silent -jsonl` re-check, and only after a recorded human approval.
- **Approval is recorded, tamper-evident and bound to the gate.** Each decision is chained into `audit.jsonl` together with the hash of the gate as approved; an edited gate is refused at execution. A failed chain check makes the CLI exit 4 and the dashboard stop accepting decisions.
- **The dashboard is local and read-mostly.** It binds to loopback only, shows findings, the policy verdict, the report and the audit log, and records approve/deny decisions. It never launches a scan.

Details for each of these are in the sections below.

## Invoke, don't vendor

Ascent drives external open-source scanners (subfinder, httpx, katana, nuclei) as subprocesses through a scope-checked runner. They are invoked, never vendored or linked into the Ascent binary.

Triage uses [Crux](https://github.com/Aldiharley/crux), the author's Apache-2.0 triage engine, linked as a library (`crux = { path = "../crux", default-features = false }`). With default features off, Crux's HTTPS client is compiled out, so the `ascent` CLI binary links no network code and triage runs Crux's offline `MockTriager`. The separate `dashboard` binary serves loopback-only HTTP (see below).

## Building

Crux is a path dependency, so check it out next to Ascent:

```
Projects/
  Ascent/
  crux/
```

Then run `cargo test` in `Ascent/`.

## SAST track

Besides the black-box (DAST) track, Ascent can run a white-box source-analysis (SAST/SCA/secrets) track over a source directory. It invokes [opengrep](https://github.com/opengrep/opengrep), [gitleaks](https://github.com/gitleaks/gitleaks) and [trivy](https://github.com/aquasecurity/trivy) as subprocesses; like the DAST tools, they are invoked, never vendored. Install whichever you want on your `PATH`. Tools that are not installed are skipped, and the run still completes (with fewer or no SAST findings). With a policy, though, a missing analyser for one of the policy's `fail_on.categories` (opengrep → SAST, gitleaks → SECRETS, trivy → SCA) makes the gate INCOMPLETE (exit 3): an unscanned category never passes.

Point the track at a source root either way:

- add `source: <dir>` to the engagement YAML, or
- pass `--source <dir>` (overrides the engagement's `source`; it must stay inside the engagement's authorised source root).

```
cargo run -- run --engagement samples/engagement.example.yaml --out out --source path/to/repo
```

SAST findings join the DAST queue and flow through the same triage, `report.md` and audit log. With no hosts or urls in scope, the DAST track is skipped and only the SAST track runs. Findings from gitleaks are redacted: the secret value is never stored.

**Your source never leaves the machine**, and no analyser is ever pointed at a network target (SAST runs locally over files). But note the analyser *subprocesses* make their own outbound calls that Ascent does not gate: opengrep's `--config auto` fetches rules from the opengrep registry (telemetry is disabled with `--metrics=off`), and `trivy fs` updates its vulnerability database from a registry. Neither sends your source or engagement targets anywhere. For an air-gapped or fully governed run, use a pinned local opengrep ruleset and `trivy --skip-db-update --offline-scan` (a planned follow-up; see `docs/followups-sast.md`).

## DAST track

The DAST track tests running web targets with [nuclei](https://github.com/projectdiscovery/nuclei), after ProjectDiscovery httpx probes the hosts and katana crawls them. It runs when the engagement lists `hosts` or `urls`. This section describes what it covers, and what it deliberately does not.

### How the surface is built

- **The whole declared scope is used.** The seed is every host (through recon) plus every URL in the engagement, de-duplicated. Hosts and URLs are no longer alternatives: a URL is scanned even when hosts are also listed.
- **Recon per host.** Each host is probed with httpx on the default web ports. subfinder runs only for real DNS names (a name with at least one dot that is not an IP literal); `localhost`, other single-label names and IP addresses are probed directly.
- **Crawl.** katana crawls the seed with `-fs fqdn`, so it stays on the exact hostnames it was given. katana's own default is the whole root domain, which Ascent does not use.
- **Scope filter.** Seeds and crawl results that the scope guard does not accept are dropped, counted and never sent to a scanner. A crawl that finds links to GitHub or a CDN no longer aborts the run. The counts are printed and stored in `run.json` under `dast`: `seeded`, `crawled`, `out_of_scope_dropped` and `scanned`.

### Profiles

Set the profile in the engagement file (`dast.profile`) or in the New Scan screen. The default is `standard`.

```yaml
dast:
  profile: standard   # passive | standard | active
```

| Profile | nuclei tags | Also excluded | Extra pass |
|---|---|---|---|
| `passive` | `tech, misconfig, exposure, headers, cors, cookie, session` | `intrusive, fuzz` | none |
| `standard` (default) | the passive tags plus `cve, sqli, xss, auth-bypass, jwt, idor, csrf, redirect, ssrf, lfi` | `fuzz` | none |
| `active` | same as standard | `fuzz` in the first pass | a second `nuclei -dast` pass (parameter-fuzzing templates) over the same surface |

Every pass of every profile uses `-rate-limit 50` (50 requests per second), `-concurrency 10` and `-timeout 10`, and always excludes the tags `dos`, `brute-force` and `default-login`. These exclusions are fixed in code and cannot be changed from the engagement file. `active` sends fuzzing payloads at every parameter it finds, so use it only on targets you are allowed to test actively. Findings from both `active` passes are merged and de-duplicated by template id and matched URL.

### Authenticated scanning

Many findings sit behind a login. Ascent supports one static request header, which covers a bearer token or a session cookie:

```yaml
dast:
  auth:
    header: Authorization          # the header name only
    value_env: ASCENT_DAST_AUTH    # the environment variable that holds the value
```

```
export ASCENT_DAST_AUTH="Bearer <token>"
ascent run --engagement engagements/<name>.yaml --out out
```

- The header is sent by both nuclei and katana, so the crawl is authenticated too.
- The engagement file holds only the header name and the variable name. The value is never written to `run.json`, `queue.json`, `report.md`, `gate.json`, the SARIF files, `dast-coverage.json` or `audit.jsonl`. It is replaced with `***` in the raw scanner results and in DAST error text before anything is written.
- It fails closed. If auth is configured and the variable is unset, empty or contains a line break, the run exits 2 before any scan starts, rather than silently scanning unauthenticated.
- **Caveat:** the value is passed to nuclei and katana as a command-line argument, so other users on the same machine can read it from the process list while a scan runs. Use a short-lived token, and do not run an authenticated scan on a shared host.
- Form-login automation, OAuth flows and token refresh are not supported (see `docs/followups-policy-gate.md`).

### Coverage matrix

A scan that finds nothing is only reassuring if you know what it tested. Every run with DAST scope writes `out/dast-coverage.json` and appends a "DAST coverage" table to `report.md`, which the dashboard's Report screen shows. For each category it states whether it was `tested`, `limited` or `not_tested`, why, and how many raw nuclei results carried one of its tags (counted before triage). If no in-scope URL was actually scanned, every category is `not_tested`, whatever the profile says. A category that needs a higher profile than the one chosen is `not_tested` with the reason "enable the standard profile" (or `active`).

### Mapping to a commercial DAST checklist

The checklist below is the one commercial DAST products such as Veracode DAST are usually compared on. Ascent is a black-box template scanner, not a full application-aware scanner, and the table says where that matters.

| Checklist item | Ascent | Notes |
|---|---|---|
| SQL injection | `standard` | nuclei `sqli` templates; `active` adds parameter fuzzing. |
| Cross-site scripting | `standard` | nuclei `xss` templates; `active` adds parameter fuzzing. |
| Authentication bypass | `standard` | `auth-bypass` and `jwt` templates. |
| Authorization flaws (IDOR) | `limited` | Only the generic `idor` templates (12 on nuclei 3.11.1). Most access-control bugs need app-specific logic and two users, which Ascent does not model. |
| CORS misconfiguration | `passive` and up | `cors` templates. |
| Security headers | `passive` and up | `headers` templates. |
| Session management | `passive` and up | `session` and `cookie` templates; `csrf` from `standard`. The template sets are small (8 `session`/`cookie` and 5 `csrf` on nuclei 3.11.1). |
| Rate limiting | not tested, by design | It needs load generation, and Ascent never floods a target. Reported as `not_tested` in every profile. |
| SSRF, path traversal, open redirect | `standard` | `ssrf`, `lfi` and `redirect` templates (`active` adds fuzzing). Not part of the usual checklist, covered anyway. |
| Known CVEs, exposures, misconfiguration | `passive` and up | `tech`, `misconfig`, `exposure`; `cve` from `standard`. |
| Authenticated scanning | static header | One header from an environment variable. No scripted login. |
| "Validate exploitability" | human-gated, detect-only re-test | After triage, `--propose` writes a re-check gate that a person approves before anything runs (see [Human-gated verification](#human-gated-verification-phase-5)). It is a detect-only `nuclei -id <id> -u <url>` re-run, not an exploit. Findings from the `active` fuzzing pass cannot be re-checked by this gate. |

Coverage depends on the installed nuclei templates, so the counts differ by version and between machines. Run `nuclei -tl -tags <tag>` to see what is installed locally.

## Dashboard

A local web dashboard (axum backend, React UI) shows the triaged findings, the pending human-approval gates, the report and the hash-chained audit log, and has a New Scan screen that validates targets and writes an engagement scope file.

![Ascent report screen: the ranked markdown report rendered in the dashboard](docs/images/dashboard-report.png)

*The Report screen renders the ranked `report.md` from the out dir.*

1. Produce an out dir with the pipeline:

   ```
   cargo run -- run --engagement samples/engagement.example.yaml --out out
   ```

   (Or install the CLI with `cargo install --path .` and run `ascent run --engagement samples/engagement.example.yaml --out out`.)

   The dashboard reads `queue.json`, `audit.jsonl` and `report.md` from it.

2. Put the pending approval gates there (until the exploitation stage populates them):

   ```
   cp samples/gates.example.json out/gates.json
   ```

3. Build the UI:

   ```
   cd frontend && npm ci && npm run build
   ```

4. Run the dashboard from the repo root:

   ```
   ASCENT_OUT=out cargo run --bin dashboard
   ```

   `ASCENT_ENG` points at the engagement file shown in the topbar (default `samples/engagement.example.yaml`; New Scan repoints it at the file it writes). `ASCENT_DIST` points at the built UI (default: `frontend/dist` inside the crate, so it works from any working directory).

5. Open <http://127.0.0.1:8787>.

Safety properties:

- It binds to loopback (`127.0.0.1:8787`) only.
- It never transmits findings anywhere. The UI only fetches its own backend's `/api/*`; the only third-party requests are the Google Fonts stylesheet and font files, which carry no finding data. The Content-Security-Policy enforces this.
- Every response carries `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`, so another page cannot frame the dashboard to trick a click on Approve.
- Approve and Deny only record a decision in the hash-chained audit log. They never run the command; the exploitation stage consumes approvals.
- The backend rejects any request whose `Host` is not `127.0.0.1:8787` or `localhost:8787`. Every POST also needs `Origin: http://127.0.0.1:8787` (or the `localhost` equivalent) and `X-Ascent: 1`. Non-browser clients must send both headers, for example:

  ```
  curl -X POST http://127.0.0.1:8787/api/gates/g1/approve \
    -H "Origin: http://127.0.0.1:8787" \
    -H "X-Ascent: 1"
  ```

- Approve is refused (HTTP 422) unless the gate's `in_scope` is `true`; Deny is always allowed. Each decision records `gate_hash`, the hash of the gate as approved, inside the chained entry.
- The New Scan screen only validates targets and writes an engagement file under `engagements/`. It never starts a run, and it refuses ambiguous or malformed targets without writing anything.

> **Warning:** don't decide gates while an `ascent run` is writing to the same out dir. The audit log is hash-chained and a concurrent append would break the chain; the dashboard then refuses further decisions (it fails closed).

Dev loop: with the backend running, `cd frontend && npm run dev` serves the UI with hot reload and proxies `/api` to it.

## Human-gated verification (Phase 5)

After triage, Ascent can propose a safe, detect-only re-check for each confirmed-looking DAST finding. A human reviews and approves it, and only then does anything run.

![Approval gates screen: a DETECT-ONLY gate showing the exact allow-listed nuclei command, expected evidence, why it might fail, the in-scope marker and Approve and Deny buttons](docs/images/dashboard-approval-gate.png)

*A gate shows the exact command, the expected evidence and why it might fail. Approving records consent; it does not run the command.*

1. Propose. `--propose` runs after triage, re-reads `<out>/queue.json`, and for every `TRUE_POSITIVE` nuclei finding with confidence at or above `--min-confidence` (default `0.8`) writes an inert proposed gate into `<out>/gates.json`. The gate is a nuclei re-check: `nuclei -id <id> -u <url> -silent -jsonl`.

   ```
   ascent run --engagement samples/engagement.example.yaml --out out --propose [--min-confidence 0.8]
   ```

2. Review and decide. Start the dashboard (see above) and open the Approval gates screen. Each gate shows a DETECT-ONLY badge, the command, the target, the expected evidence, why it might fail, and whether the target is in scope. Click Approve or Deny. Approve records a hash-chained `gate_decision` bound to the gate's `gate_hash`. (Non-browser clients can `POST /api/gates/<id>/approve` with `Origin: http://127.0.0.1:8787` and `X-Ascent: 1`.)

3. Verify. This runs only the approved gates:

   ```
   ascent verify --engagement samples/engagement.example.yaml --out out
   ```

   It prints `confirmed=N not_confirmed=N refused=N` and appends one `gate_execution` entry per gate to the audit log. Gates that already have an execution entry are skipped.

Invariants:

- Nothing runs without a recorded human approval.
- An edited gate is refused. The `gate_hash` is recomputed at execution and must match the one the human approved; on a mismatch the gate is Refused without running.
- Scope is re-checked at execution, against the `-u` target in the command that will actually run (which must equal the gate's `target`), not just at proposal time.
- Only detect-only, allow-listed nuclei re-checks run. The command is executed as an argv list, never through a shell.
- The hard exclusions are not built: no autonomous firing, C2, lateral movement, persistence, exfiltration, autonomous privilege escalation, or exploit-tier tools.

Requirements: `ascent verify` needs nuclei installed and a reachable, in-scope target. `--propose` only produces gates after a real scan that found nuclei DAST findings; with no such findings, `gates.json` gets no new gates. With no approved gates, `verify` runs nothing and reports all zeros.

## Policy gate and CI

`ascent run … --policy ascent-policy.yaml` evaluates a policy after triage and
exits with a CI-friendly code; `ascent gate --policy … --out out` evaluates an
existing output directory. Every run also writes native SARIF 2.1.0
(`out/ascent.sarif` for code findings, `out/ascent-dast.sarif` for URL findings;
regenerate with `ascent sarif`). See `samples/ascent-policy.example.yaml` and
`docs/ci/github-actions.yml`.

```
ascent run --engagement engagement.yaml --source . --out out --policy ascent-policy.yaml --fail-on-warn
ascent gate --policy ascent-policy.yaml --out out --fail-on-warn
ascent sarif --out out --source-root path/to/repo
```

nuclei (and the ProjectDiscovery recon tools) are only required when the
engagement has DAST scope (`hosts` or `urls`); a source-only engagement needs
just the SAST analysers. A missing analyser for a policy category makes the
gate INCOMPLETE.

| Exit | Meaning |
|---|---|
| 0 | PASS, or CONDITIONAL (warnings only) — or no policy given |
| 1 | FAIL (or CONDITIONAL with `--fail-on-warn`) |
| 2 | Usage or configuration error (bad engagement, malformed policy, bad `--source`) |
| 3 | INCOMPLETE: a scanner or stage failed, a policy category's analyser is not installed, or it was a dry run — never a pass |
| 4 | The audit hash chain failed verification (`ascent run` then refuses to start) |

The verdict is written to `out/gate.json` and chained into `audit.jsonl`
(`gate_evaluation`). A finding Crux triages as LIKELY_FALSE_POSITIVE is demoted
to a warning, never silently passed. Findings carry a stable `ascent/v1`
fingerprint (no line numbers; secrets keyed on rule + path only). Credential-class
findings (gitleaks, CWE-798/259/321) carry no secret value or derivative; other
SAST evidence stays local in `queue.json`/`report.md`. Runtime errors now exit 3 (previously 1), so
1 always means "policy failed".

## License

Apache-2.0. See [LICENSE](LICENSE).
