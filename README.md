# Ascent

Ascent is an open-source, scope-enforced, human-in-the-loop AppSec pipeline, written in Rust.

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

Besides the black-box (DAST) track, Ascent can run a white-box source-analysis (SAST/SCA/secrets) track over a source directory. It invokes [opengrep](https://github.com/opengrep/opengrep), [gitleaks](https://github.com/gitleaks/gitleaks) and [trivy](https://github.com/aquasecurity/trivy) as subprocesses; like the DAST tools, they are invoked, never vendored. Install whichever you want on your `PATH`. Tools that are not installed are skipped, and the run still completes (with fewer or no SAST findings).

Point the track at a source root either way:

- add `source: <dir>` to the engagement YAML, or
- pass `--source <dir>` (overrides the engagement's `source`; it must stay inside the engagement's authorised source root).

```
cargo run -- run --engagement samples/engagement.example.yaml --out out --source path/to/repo
```

SAST findings join the DAST queue and flow through the same triage, `report.md` and audit log. With no hosts or urls in scope, the DAST track is skipped and only the SAST track runs. Findings from gitleaks are redacted: the secret value is never stored.

## Dashboard

A local web dashboard shows the triaged findings, the pending human-approval gates, the report and the hash-chained audit log.

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

   `ASCENT_ENG` points at the engagement file shown in the topbar (default `samples/engagement.example.yaml`). `ASCENT_DIST` points at the built UI (default: `frontend/dist` inside the crate, so it works from any working directory).

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

> **Warning:** don't decide gates while an `ascent run` is writing to the same out dir. The audit log is hash-chained and a concurrent append would break the chain; the dashboard then refuses further decisions (it fails closed).

Dev loop: with the backend running, `cd frontend && npm run dev` serves the UI with hot reload and proxies `/api` to it.

## License

Apache-2.0. See [LICENSE](LICENSE).
