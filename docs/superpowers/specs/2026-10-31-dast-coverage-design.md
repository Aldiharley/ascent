# DAST surface fixes and Veracode-parity coverage — design

Date: 2026-10-31
Status: approved for build (user: "fix the DAST gaps first … match up" with Veracode DAST)
Inputs: `docs/research/2026-10-30-veracode-gap-analysis.md`, `docs/followups-pipeline-core.md`,
the SecAI Veracode page's DAST checklist, and the installed nuclei v3.11.1 template inventory.

## Problem

Ascent's DAST track has three bugs and a coverage gap.

Bugs (verified by reading `src/pipeline.rs`, `src/stages/{recon,enumerate,scan}.rs`):
1. **Only the first host is scanned, and `urls` are ignored whenever any host is set.**
   `run_pipeline` takes `eng.hosts.first()` as the recon root; other hosts and all `eng.urls`
   are dropped. The sample engagement (`hosts: [localhost]` + `urls: [http://localhost:3000/]`)
   therefore never scans Juice Shop on :3000 (httpx probes only default ports).
2. **One off-scope link aborts the whole DAST scan.** `enumerate_surface` merges every katana
   `endpoint` unchecked; `scan` then hands all their hosts to the scope-checking runner, which
   refuses the entire nuclei invocation. A crawl of any real app (links to GitHub, CDNs …)
   ends the run with exit 3 and zero DAST findings.
3. **Scope-file typos are silent.** `Engagement` has no `deny_unknown_fields`, so a misspelt
   key silently shrinks scope.

Coverage gap: nuclei runs only `-tags cve,exposure,misconfig,tech`. The DAST checklist
(SQL injection, XSS, authentication bypass, authorization flaws, CORS, security headers,
session management, rate limiting) is mostly untested, there is no authenticated scanning,
and nothing tells the user what was and was not tested. Real Veracode DAST (per the research)
offers authenticated scanning and black-box coverage of these classes; its "validates
exploitability" is a marketing claim — Ascent's human-gated detect-only re-test already
exceeds it.

## Goals

1. Scan the whole declared scope: every host (recon) **and** every URL, unioned.
2. Out-of-scope crawl results are **dropped and counted**, never sent to a scanner, never
   abort the run.
3. Engagement files reject unknown keys (exit 2).
4. Three explicit DAST **profiles** mapped to real nuclei templates, chosen per engagement.
5. **Authenticated scanning** via one request header whose value comes from an environment
   variable — never written to any file Ascent produces.
6. A **DAST coverage matrix** (`out/dast-coverage.json` + a report section) that states, per
   checklist category, whether it was tested, with which templates, and how many findings —
   and honestly marks what is not tested and why.
7. The New Scan screen can set the profile and the auth header *name* + env var *name*.

## Non-goals

- Load / rate-limit flooding or DoS testing (never; `dos` and `brute-force` are always excluded).
- Credential guessing: `default-login` templates are always excluded.
- Login-flow automation (form login, OAuth, Selenium scripts) — a static header covers bearer
  tokens and session cookies; scripted login is a follow-up.
- OpenAPI/GraphQL schema import, headless JS crawling — follow-ups.
- Widening the verification allow-list (fuzz-template findings cannot be re-checked by the
  current `nuclei -id … -u …` gate; documented limitation).

## Engagement schema additions

```yaml
dast:
  profile: standard          # passive | standard | active   (default: standard)
  auth:                      # optional
    header: Authorization    # header NAME only
    value_env: ASCENT_DAST_AUTH   # env var holding the value, e.g. "Bearer eyJ…"
```

- `Engagement` and every nested struct get `#[serde(deny_unknown_fields)]`.
- `dast` is optional; absent → `profile: standard`, no auth.
- `auth.header` must be an RFC 7230 token (`[!#$%&'*+.^_`|~0-9A-Za-z-]+`); `value_env` must be
  `[A-Z_][A-Z0-9_]*`. Validation failures → exit 2.
- At run time (non-dry-run, DAST scope present) the env var must be set, non-empty and free of
  CR/LF; otherwise exit 2 ("fail closed: refusing to scan unauthenticated when auth is
  configured").

## Surface

`seed = recon(each host) ∪ eng.urls` (deduplicated, sorted):
- For each host: if it is a DNS name with at least one dot (not an IP literal, not a single
  label like `localhost`), run subfinder on it; always include the host itself; probe with
  httpx (default ports). Single-label/IP hosts skip subfinder.
- `surface = enumerate(seed)` (katana, auth header applied), then **filter**: keep only URLs
  the engagement `ScopeGuard` accepts; count the rest as `out_of_scope_dropped`.
- `run.json` gains `dast: {profile, authenticated, auth_header, seeded, crawled,
  out_of_scope_dropped, scanned}` (`auth_header` is the header **name**; `#[serde(default)]`
  so old run.json files still load). `Summary.urls` = scanned count.

## Profiles → nuclei invocations

All profiles: `-silent -jsonl -rate-limit 50 -concurrency 10 -timeout 10`, plus
`-H "<Name>: <value>"` when auth is configured, and `-etags dos,brute-force,default-login`.

| Profile | `-tags` | Extra `-etags` | Extra pass |
|---|---|---|---|
| passive | `tech,misconfig,exposure,headers,cors,cookie,session` | `intrusive,fuzz` | — |
| standard (default) | passive tags + `cve,sqli,xss,auth-bypass,jwt,idor,csrf,redirect,ssrf,lfi` | `fuzz` | — |
| active | same as standard | `fuzz` | a second pass `nuclei -dast …` (parameter fuzzing templates) over the same surface |

katana gets the same `-H` when auth is configured. Both passes' findings are normalised and
merged. Any nuclei pass failing → the stage errors (exit 3, fail closed), as today.

## Coverage matrix

A fixed registry of checklist categories (Veracode/SecAI DAST list + the extra classes Ascent
covers), each with the nuclei tags that implement it and the minimum profile:

| id | Category | Tags | Min profile |
|---|---|---|---|
| sqli | SQL injection | sqli | standard (+ fuzzing in active) |
| xss | Cross-site scripting | xss | standard (+ fuzzing in active) |
| auth-bypass | Authentication bypass | auth-bypass, jwt | standard |
| authz | Authorization flaws (IDOR) | idor | standard — marked `limited` (12 templates; IDOR mostly needs app-specific logic) |
| cors | CORS misconfiguration | cors | passive |
| headers | Security headers | headers | passive |
| session | Session management | session, cookie, csrf | passive (csrf: standard) |
| rate-limit | API rate limiting | — | never — `not_tested`: "needs load generation; Ascent never floods a target" |
| ssrf / lfi / redirect | SSRF, path traversal, open redirect | ssrf / lfi / redirect | standard |
| known-vulns | Known CVEs, exposures, misconfiguration | cve, exposure, misconfig, tech | passive (cve: standard) |

`out/dast-coverage.json`: `{profile, authenticated, categories: [{id, name, tags, status:
"tested"|"limited"|"not_tested", reason, findings}]}`. `findings` counts raw nuclei results
whose `info.tags` intersect the category's tags (before triage). `report.md` gets a
"DAST coverage" table. Written only when DAST ran (removed at run start like other outputs).

## Secret hygiene (authenticated scanning)

- The header value lives only in the process environment and in the scanner argv.
- It must never appear in `run.json`, `queue.json`, `report.md`, `gate.json`, SARIF,
  `dast-coverage.json`, `audit.jsonl`, or Ascent's error messages: DAST stage errors are
  scrubbed (value replaced by `***`).
- Test: a pipeline run with a fake runner and a known value; assert the value occurs in no
  output file and not in the returned error text.
- Documented caveat: argv is visible to other local users of the machine via the process list.

## Dashboard

New Scan gains a "DAST profile" select (passive / standard / active, default standard; active
labelled "adds parameter fuzzing — use only on targets you may actively test") and two
optional fields "Auth header name" + "Env var holding its value" (never the value itself).
`POST /api/engagements` validates them with the same rules and writes the `dast` block.
The Report screen shows the coverage section (it renders report.md). No new assets.

## Testing

Unit: engagement parsing (defaults, unknown keys rejected, header/env validation), surface
seeding (all hosts + urls; subfinder skipped for IP/single-label), out-of-scope filtering with
counts, profile → argv (tags/etags/`-dast`/`-H`/rate limits), coverage computation, secret
non-leak, missing env var → ConfigError. CLI: unknown engagement key → exit 2; auth configured
with env unset → exit 2. Frontend: New Scan profile/auth fields posted; validation error shown.
Live: Juice Shop (`bkimminich/juice-shop`, bound to 127.0.0.1:3000) with the juiceshop
engagement under `standard` and `active`: findings across several categories, coverage json
present, off-scope crawl links dropped (not aborting), gate evaluates.
