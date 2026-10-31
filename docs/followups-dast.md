# Ascent DAST coverage and dashboard redesign: follow-ups

These come out of the reviews and live validation of `feat/dast-coverage` and `feat/ui-redesign` (both merged into `main` on 2026-10-31). None of them blocks the merge. Items are grouped by area, most important first. Related items live in `docs/followups-pipeline-core.md` (items 4 to 7: scope hardening, engagement validation, redirect audit, nuclei egress) and `docs/followups-dashboard.md`.

## Live validation baseline (OWASP Juice Shop on 127.0.0.1:3000, Windows 11)

| Run | Profile | Result |
|---|---|---|
| 4 | standard | 103 min, urls=25, findings=251, 287,872 requests, 1.4% errors, 0 off scope, 241 of 11,586 templates excluded, complete |
| 5 | active, authenticated, SAST fixture | 120 min, 307,073 requests, 15.5% errors, 0 off scope, no auth-header leak. The Juice Shop container died part-way, but the run still reported complete. Fixed by the post-scan re-probe. |
| 6 | standard, authenticated, SAST fixture | 104 min, urls=25, findings=280 (95 triaged), 287,869 requests, 1.3% errors, 0 off scope, `stopped_answering=[]`, complete, no leak, no temp dirs left |

Tool versions: nuclei v3.11.1, nuclei-templates v10.4.9, katana and httpx from pdtm. Juice Shop's nuclei hits are info-level and triage as ABSTAIN, so `--propose` correctly proposes 0 gates.

## DAST

1. **No wall-clock limit on a nuclei pass.** Ascent runs nuclei with `-nmhe`, so nuclei never gives up on a slow host, and a standard run against Juice Shop takes about 104 minutes. Add a per-pass (or per-run) time limit. When it is hit, stop nuclei, keep what it found, and mark the run INCOMPLETE with a reason that names the limit. Undecided: where the limit is configured (engagement file vs CLI flag) and its default.
2. **Crash-and-recover is not detected.** The post-scan re-probe catches a target that is down at the end of the scan. A target that crashes and comes back before the end (container restart policy, supervisor) is not caught, and the checks sent while it was down silently produced nothing. Detect it from the trace log: a long streak of connection errors against one host, followed by successes.
3. **A reverse proxy's 502 counts as alive.** The re-probe treats any HTTP response as an answer, so a proxy in front of a dead app looks healthy. Treating 502/503/504 as "not answering" needs a decision: a healthy target can legitimately return 503.
4. **Detection, not prevention, for off-scope requests.** See `docs/followups-pipeline-core.md` item 7. A scope-enforcing forward proxy (nuclei `-proxy`) would refuse off-scope requests instead of reporting them afterwards.
5. **nuclei flow-runtime globals unverified.** It is not yet verified whether a `flow:` can open network connections through a runtime global (such as `isPortOpen`) without `require`. Check this against the nuclei v3 source (pipeline-core item 7).
6. **Auth header name accepts hop-by-hop and framing names** (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection` …). Deny-list them in engagement validation. Tests there assert only `is_err`, not the cause.
7. **Secret scrub is exact-match only.** URL-encoded, shell-quoted or partial echoes of the auth value survive the scrub. Very short values reduce whole rows to a placeholder. The value is visible in the process list (argv) while nuclei runs; this is documented.
8. **`localhost.` (trailing dot) gives a false INCOMPLETE** in the scope audit.
9. **Windows-only:** a nuclei template path longer than 260 characters stops the run. The private trace-log TempDir relies on the per-user `%TEMP%` ACL rather than setting its own.
10. **Template listing cost.** `nuclei -tl` adds about 20 s to every live run. Cache the listing per templates version.
11. **Failing-host heuristic is coarse.** It works per hostname and counts every error kind.
12. **Docs:** in the README section "Requests outside the target", the intro says Ascent "handles this twice", but four bullets follow. Reword the intro.

## Dashboard (redesign)

1. Lint has not run: the oxlint native binding was missing on the Windows machine. Run `npm run lint` on Linux and fix what it reports. In particular, check `ref.current` writes during render (`App.tsx`, `Toast.tsx`).
2. Pressing Enter in search moves focus to the page heading. A refinement could keep focus in the field.
3. Leaving New Scan while its POST is in flight briefly shows the previous Overview payload.
4. The `.num` utility class is unused. The `.report table` CSS is unused (the report renders no GFM tables).
5. The reduced-motion test is structural only.
