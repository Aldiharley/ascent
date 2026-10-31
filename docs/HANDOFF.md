# Ascent: handoff for a new working session

This is for a session (human or agent) that continues Ascent with no prior context. Read it in full before changing anything. Last updated 2026-10-31, at commit `37a560a` plus this document.

## 1. What Ascent is and where it stands

Ascent is an open-source (Apache-2.0), scope-enforced, human-in-the-loop AppSec pipeline in Rust, with a loopback-only axum + React dashboard. `README.md` is the authoritative description. Read it first, especially "How it works", "DAST track", "Requests outside the target", and "Policy gate and CI".

Merged into `main` and pushed:

- Pipeline core, SAST track (opengrep, gitleaks, trivy), human-gated detect-only verification, policy gate and SARIF.
- **DAST coverage** (`feat/dast-coverage`):
  - profiles passive / standard / active;
  - authenticated scanning, with the header value only ever read from an env var;
  - an off-target template exclusion (`-et`);
  - a trace-log scope audit (`-tlog`), so any off-scope request makes the run INCOMPLETE;
  - failing-host and unreachable-URL detection;
  - a post-scan liveness re-probe (`dast.stopped_answering`);
  - `dast-coverage.json`.

  Plan: `docs/plans/2026-10-31-dast-coverage.md`. Spec: `docs/superpowers/specs/2026-10-31-dast-coverage-design.md`.
- **Dashboard redesign** (`feat/ui-redesign`): a clay-and-knit theme with a white fluffy watchdog mascot. Plan: `docs/plans/2026-10-31-ui-redesign.md`. Spec: `docs/superpowers/specs/2026-10-31-ui-redesign-design.md`.

Test counts on Windows at merge: 460 Rust tests (`cargo test`), 543 frontend tests (`npx vitest run`), clippy clean.

**CI on `main` is red.** It has been red since the policy-gate merge (2026-10-30), because `cargo fmt --check` fails across many files. Because that step fails first, `cargo clippy` and `cargo test` have **not run on Linux** for the last three merges. The frontend job is green.

Open work: `docs/followups-dast.md` (DAST and redesign, with the live-run baseline), `docs/followups-pipeline-core.md`, `docs/followups-policy-gate.md`, `docs/followups-dashboard.md` and `docs/followups-sast.md`.

## 2. Non-negotiable rules

1. **Scan only lab targets you started yourself on loopback**, such as OWASP Juice Shop bound to `127.0.0.1`. Never point Ascent, nuclei, katana, httpx or any other tool at any other host or network, even "just to test". The active profile is intrusive: it crashed Juice Shop on a live run.
2. **The auth header value must never appear** in any output, file, log, error, commit or chat message. For lab runs, put a made-up dummy value in the env var named by `dast.auth.value_env`. After every authenticated run, grep the whole out dir and the run log for the dummy value; the expected result is no match.
3. **The dashboard never launches scans.** New Scan only writes a scope file; runs happen from the terminal.
4. **Scanned data is rendered as React text only**: no `<img>` built from scan data, no `dangerouslySetInnerHTML`.
5. **No new crate or npm dependencies** without the owner's explicit approval.
6. **The DAST safety flags are fixed in code**, and the engagement file must not be able to change them: `-ni`, `-dr`, `-duc`, `-pt http`, `-nmhe`, `-et`, `-tlog`, rate limits, and the excluded `dos` / `brute-force` / `default-login` tags. Changing them requires a written design and the owner's approval.
7. **Fail closed.** Anything Ascent could not verify makes the run INCOMPLETE (exit 3); it is never reported as a pass.
8. **TDD.** Write a failing test, watch it fail, implement, watch it pass. Commit in small steps.
9. **Git:**
   - Work on a feature branch, never directly on `main`. Open a PR with `gh` so CI runs on Linux, and merge only when CI is green and the owner agrees.
   - End every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
   - Never force-push.
   - Never commit lab output, engagement files containing real targets, or the test fixtures described below.

## 3. Setting up a Linux (Kali) machine

Ascent's Cargo path dependency is `../crux`, so clone both repositories side by side:

```bash
mkdir -p ~/src && cd ~/src
git clone https://github.com/Aldiharley/ascent.git
git clone https://github.com/Aldiharley/crux.git
```

Toolchains:

- **Rust ≥ 1.82, via rustup** (Kali's packaged rustc may be older). Also add `rustup component add rustfmt clippy`.
- **Node ≥ 20 and npm.** CI uses 20. Then run `cd ascent/frontend && npm ci`.
- **Docker**, for the lab target.

Scanners. Ascent calls the binaries by these exact names: `nuclei`, `katana`, `httpx`, `subfinder` (optional), `opengrep`, `gitleaks`, `trivy`.

- **ProjectDiscovery httpx must be the `httpx` on `PATH`.** Kali's apt package installs ProjectDiscovery httpx as `httpx-toolkit`, and Python's `httpx` CLI can shadow the name. Install the ProjectDiscovery tools with pdtm or `go install` (into `~/.pdtm/go/bin` or `~/go/bin`), and put that directory first on `PATH` for Ascent runs. Verify that `httpx -version` prints the ProjectDiscovery banner.
- **Pin versions so results compare with the Windows baseline:** nuclei v3.11.1 and nuclei-templates v10.4.9. With these, 241 of 11,586 templates should be excluded. The template listing must print `Listing available … nuclei templates for <DIR>` with an absolute DIR, or Ascent stops the run on purpose.
- **Use `127.0.0.1`, not `localhost`**, in engagements: ProjectDiscovery tools may fail to resolve `localhost`.

Lab target (loopback only):

```bash
docker run -d --name ascent-juiceshop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Optional SAST fixture: a throwaway directory **outside the repo** containing a `creds.txt` with a fake AWS-format key pair and a `package-lock.json` pinning an old `axios`. This makes the SAST / secrets / SCA highs fire, so the policy gate has something to fail on. Never commit it.

Baseline check before any change:

```bash
cd ~/src/ascent
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cd frontend && npx vitest run && npm run build && npm run lint
```

`npm run lint` (oxlint) has never run successfully: its native binding was missing on Windows. Expect findings.

A live run is described in the README Quick start. Use `samples/engagement.juiceshop.yaml`. Optionally copy it outside the repo and enable `dast.auth` with a dummy env value. The standard profile takes about 105 minutes against Juice Shop at 50 requests per second. It is working, not stuck, if nuclei's trace log under the temp dir keeps growing. The dashboard is `target/release/dashboard` (port 8787). It writes New Scan engagement files into `./engagements` relative to its working directory, so run it from a scratch directory, not the repo root.

## 4. Work queue, in order

1. **Make CI green on Linux.**
   - Run `cargo fmt` over the whole tree as one formatting-only commit, with no logic changes.
   - Then run clippy and the full test suite on Linux, and fix anything that is Windows-specific in the tests or code.
   - Push the branch, open a PR and confirm both CI jobs pass.
   - The Node 20 deprecation annotation on the workflow is optional to address.
2. **Run `npm run lint`** and fix its findings (dashboard item 1 in `docs/followups-dast.md`).
3. **Live Linux validation, standard profile, authenticated, against Juice Shop.** Compare with run 6 in the baseline table in `docs/followups-dast.md`:
   - `complete: true`;
   - `dast.stopped_answering` empty;
   - 0 off-scope requests;
   - about 288k requests;
   - 241 templates excluded;
   - no auth-value leak;
   - no `ascent-nuclei-*` temp directories left behind.

   Record the results in `docs/followups-dast.md`.
4. **DAST items 1 to 3 in `docs/followups-dast.md`**: wall-clock limit, crash-and-recover detection, 502 handling. Each changes behaviour and needs a decision. Write a short design (problem, options, recommendation) and get the owner's approval before building. After approval, build it end to end: TDD, then review, then a live re-check.
5. **The remaining DAST items, the README wording fix and the smaller redesign items**, in the order listed.
6. **Bigger work that needs a design first:** a scope-enforcing forward proxy for nuclei (pipeline-core item 7), and the "must land before exploitation" items in `docs/followups-dashboard.md`.

Items that are specific to Windows (template paths over 260 characters, the TempDir ACL) cannot be checked on Linux. Leave them open.
