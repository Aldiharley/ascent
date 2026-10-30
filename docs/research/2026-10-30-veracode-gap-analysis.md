# Build the gate before chasing Veracode

The SecAI Framework's Veracode page labels itself "Review status: Validated", but it does not hold up against Veracode's own documentation. Of 37 claims checked, **9 are accurate, 9 are partially accurate or outdated, 14 are inaccurate or misleading, and 5 cannot be verified**. Every copy-pasteable artefact on the page fails except one: the pre-commit command, the policy YAML, two of the three Azure DevOps tasks, the `veracode_fix` config and the axios CVE example. The exception is the `Veracode@3` task block ([SecAI page](https://zimaxnet.github.io/secai-framework/security-tools/veracode.html); [Veracode Azure DevOps Extension](https://docs.veracode.com/r/Azure_DevOps_Extension)). Do not use the page as a specification. Use the real Veracode mechanics instead, and those turn out to be simpler than the page suggests. Veracode's core value is a **policy verdict that fails the build** (Passed / Did Not Pass / Conditional Pass), kept honest by baselines, grace periods and approved mitigations ([Veracode: Application security policies](https://docs.veracode.com/r/c_appsec_policies)). That verdict is exactly what Ascent lacks. A successful Ascent run always exits 0. Ascent has no policy evaluation, no run-to-run delta, no waivers and no SARIF output (Ascent source code, src/pipeline.rs). Its scanners are not the problem. Ascent's two Critical gaps are **policy evaluation and CI exit-code gating**, and both can be closed with open standards: a versioned YAML policy, SARIF 2.1.0 `baselineState` and `suppressions`, trivy's license and image scanners, and the de-facto 0/1/2 exit-code convention. Ascent is already ahead of Veracode in three areas: tamper-evident auditing, targeted human-gated re-testing and fail-closed scope enforcement. Automatic fix PRs and AI-generated patches should remain deliberate non-goals.

## Part 1 — The "Validated" SecAI page fails on its runnable details

The page's accurate claims are mostly generic: Veracode does SAST, DAST and SCA, it was founded in 2006 in Burlington, and it is a Gartner Leader. Its inaccuracies are concentrated in specifics an engineer would copy. The pre-commit hook calls a `veracode pipeline-scan` subcommand that does not exist, and it mixes the underscore flags of `pipeline-scan.jar` with the hyphenated flags of the `veracode static scan` CLI. It also passes `--fail_on_severity high`, but the documented syntax is a quoted list of capitalised labels such as `"Very High, High"`. The `--output_file` flag it uses does not exist ([Pipeline Scan parameters](https://docs.veracode.com/r/Pipeline_Scan_parameters); [veracode static scan](https://docs.veracode.com/r/veracode_static_scan)). The policy YAML invents a **WARN state Veracode does not have**. Veracode's four states are Not Assessed, Passed, Did Not Pass and Conditional Pass. Policies are platform or API objects, not YAML files. The page's compound "High AND CVSS < 7.5" rule also cannot be expressed, because Veracode rule types are single-criterion ([Application security policies](https://docs.veracode.com/r/c_appsec_policies); [General security policy rules](https://docs.veracode.com/r/General_security_policy_rules)).

The sample findings break down on inspection. The SAST example labels a forwarded API-key header as **CWE-918 SSRF** even though the destination URL is hard-coded. CWE-918 requires attacker influence over the destination, and the page's own "fix" is an authentication allow-list, not an SSRF control ([MITRE CWE-918](https://cwe.mitre.org/data/definitions/918.html)). The SCA example calls **CVE-2021-3749 an SSRF with CVSS 9.1**. NVD and GitHub both record it as a ReDoS rated 7.5 High with availability-only impact, first fixed in axios 0.21.2 ([NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3749); [GHSA-cph5-m8f7-6c5x](https://github.com/advisories/GHSA-cph5-m8f7-6c5x)). The page appears to have confused it with CVE-2020-28168, an SSRF that was fixed in 0.21.1, the very version the page calls vulnerable ([axios changelog](https://raw.githubusercontent.com/axios/axios/v0.x/CHANGELOG.md)).

| # | SecAI claim | Verdict | Evidence |
|---|---|---|---|
| 1 | Founded 2006, Burlington MA | Accurate | [Wikipedia](https://en.wikipedia.org/wiki/Veracode) |
| 2 | Founders "Chris Wysopal, Chris Eng, and others from @stake" | Partially accurate | Wysopal is correct. The documented co-founder is Christien Rioux, and no source found lists Eng ([Wikipedia](https://en.wikipedia.org/wiki/Veracode)) |
| 3 | Part of the Thoma Bravo portfolio | Outdated | TA Associates has been majority owner since 2022, and Thoma Bravo keeps a minority stake ([Veracode PR](https://www.veracode.com/press-release/veracode-receives-major-growth-investment-ta-associates)) |
| 4 | Gartner MQ Leader | Accurate (uncited on page) | Named a Leader in the 2025 AST MQ for the 11th time ([Veracode PR](https://www.veracode.com/press-release/veracode-named-a-leader-in-the-gartner-magic-quadrant-application-security-testing-for-11th-consecutive-time/)) |
| 5 | SAST supports "120+ languages" | Inaccurate (inflated) | Veracode says "more than 100 languages and frameworks" ([Veracode](https://www.veracode.com/security/static-analysis-tool)) |
| 6 | SAST uses data-flow, control-flow and taint analysis | Unverifiable (plausible) | No official technique page found |
| 7 | SAST example is CWE-918 SSRF | Inaccurate | The destination is fixed, so the issue is authentication, not SSRF ([MITRE](https://cwe.mitre.org/data/definitions/918.html)) |
| 8 | `veracode pipeline-scan ... --fail_on_severity high --output_file` | Inaccurate | No such subcommand, wrong severity syntax, and the flag does not exist ([parameters](https://docs.veracode.com/r/Pipeline_Scan_parameters)) |
| 9 | Policy YAML with FAIL/WARN, compound CVSS rule, 30-day WARN, secrets rule | Inaccurate | No YAML policies, no WARN state, single-criterion rules, no secrets rule type ([policies](https://docs.veracode.com/r/c_appsec_policies); [rules](https://docs.veracode.com/r/General_security_policy_rules)) |
| 10 | ADO `Veracode@3` with `veracodeAppProfile`, `createProfile`, `importResults`, `failBuildOnPolicyFail` | Accurate | [ADO extension](https://docs.veracode.com/r/Azure_DevOps_Extension) |
| 11 | `Veracode@3` `sandboxName`, `failBuildIfUploadAndScanBuildStepFails` | Partially accurate / unverified | `sandboxName` is confirmed only on Flaw Importer. Upload and Scan lists `createSandBox` ([ADO extension](https://docs.veracode.com/r/Azure_DevOps_Extension)) |
| 12 | ADO `VeracodeSCA@1` with `failOnCVSS: 7.0` | Inaccurate | The official extension documents only Upload and Scan and Flaw Importer ([ADO extension](https://docs.veracode.com/r/Azure_DevOps_Extension)) |
| 13 | ADO `VeracodeContainerScan@1` | Inaccurate | Same source; no such task |
| 14 | SCA covers direct and transitive dependencies, licenses, outdated packages and CVEs | Accurate (one caveat) | Default "outdated" issues apply only to direct libraries ([default rules](https://docs.veracode.com/r/About_Veracode_Default_Rules_for_Agent_Based_Scanning)) |
| 15 | CVE-2021-3749 is SSRF | Inaccurate | It is ReDoS, CWE-1333/400 ([NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3749)) |
| 16 | CVSS 9.1 Critical | Inaccurate | 7.5 High, `A:H` only ([GHSA](https://github.com/advisories/GHSA-cph5-m8f7-6c5x)) |
| 17 | axios@0.21.1 is vulnerable | Accurate | Versions ≤ 0.21.1 are affected ([NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3749)) |
| 18 | Fix: upgrade to 0.21.4 | Partially accurate | 0.21.4 is patched, but the minimal fix is 0.21.2 ([GHSA](https://github.com/advisories/GHSA-cph5-m8f7-6c5x)) |
| 19 | "Pull Request: auto-created by Veracode" | Partially accurate | Requires an agent scan with `--update-advisor --pull-request`. npm is supported, Yarn is not ([Automatic PRs](https://docs.veracode.com/r/About_Automatic_Pull_Requests)) |
| 20 | `veracode_fix:` YAML with `auto_pr_conditions` including test coverage > 80% | Inaccurate | The real directives are `pr_on`, `no_breaking_updates` and `ignore_closed_prs`. None of them involves test coverage ([directives](https://docs.veracode.com/r/Automatic_Pull_Request_Scan_Directives)) |
| 21 | PR title "Fix CVE-2024-12345 in axios" | Inaccurate (placeholder ID) | Not a real axios CVE ([SecAI page](https://zimaxnet.github.io/secai-framework/security-tools/veracode.html)) |
| 22 | Container scan of a devcontainer image reports CVEs | Accurate (capability; results illustrative) | [veracode scan](https://docs.veracode.com/r/veracode_scan) |
| 23 | Secret detected in a Dockerfile `ENV` line | Accurate (capability) | [Run Container Security scans](https://docs.veracode.com/r/Run_Container_Security_scans) |
| 24 | "malware_scan: Clean, 1,247 files scanned" | Inaccurate / unsupported | No Veracode container documentation mentions malware scanning ([product page](https://www.veracode.com/products/container-security/)) |
| 25 | DAST is black-box testing of the running app | Accurate | [Dynamic Analysis](https://docs.veracode.com/r/Dynamic_Analysis) |
| 26 | DAST category list (SQLi, XSS, authz, rate limiting, CORS, headers, sessions) | Partially accurate / unverifiable | Standard DAST checks, but not itemised in the Veracode docs |
| 27 | DAST "validates exploitability" | Partially accurate | A marketing claim. DAST Essentials gives replayable payloads, and no automated proof-of-exploit is documented ([DAST Essentials blog](https://www.veracode.com/blog/intro-appsec/getting-started-guide-veracode-dast-essentials)) |
| 28 | Fix-verification lifecycle ("all instances fixed?", "no new vulns introduced?", "mark resolved") | Partially accurate | The rescan-and-compare loop is real. The verification steps are not documented ([Matching flaws](https://docs.veracode.com/r/Matching_flaws_between_scans)) |
| 29 | IDE: red squiggles, hover details, quick-fix suggestions | Accurate (VS Code extension) | [Veracode Scan for VS Code](https://docs.veracode.com/r/Veracode_Scan_for_VS_Code) |
| 30 | IDE: "link to full report" | Inaccurate | IDE results are explicitly not available in the Platform (same source) |
| 31 | Integration "in Cursor" | Unverifiable as official | The extension is on Open VSX under a verified namespace, but no Veracode document names Cursor ([Open VSX](https://open-vsx.org/api/-/search?query=veracode)) |
| 32 | "Similar to ESLint but for security" | Misleading | Scans run "on demand, not as you type", with a 60-minute cap ([VS Code doc](https://docs.veracode.com/r/Veracode_Scan_for_VS_Code)) |
| 33 | "$15K–50K per application per year" | Unverifiable (likely inflated) | No public pricing. Vendr reports an average total contract of about $53K a year ([Vendr](https://vendr.com/marketplace/veracode)) |
| 34 | "~$260K/year for 10 apps" | Unverifiable | The page's own arithmetic, near Vendr's observed maximum of about $334K |
| 35 | "Unlimited scans, all scan types" included | Inaccurate | DAST concurrency is a purchased scan-capacity subscription ([Dynamic Analysis](https://docs.veracode.com/r/Dynamic_Analysis)) |
| 36 | "Prevent 1 breach: $4M saved" | Partially accurate | Roughly matches IBM's $4.44M global average for 2025, but the page cites nothing ([CyberScoop](https://cyberscoop.com/ibm-cost-data-breach-2025/)) |
| 37 | "Required for SOC 2 and PCI-DSS" | Not verified | The research did not check this. Neither framework is known to mandate a specific vendor, but no source was retrieved |

**Overall assessment.** The page reads as illustrative, probably machine-generated content that was never run against real tooling. Its "Review status: Validated" label is not credible. Its errors are invented syntax, invented states, a misclassified CWE and a misdescribed CVE, which are the kinds of mistakes a single execution or lookup would have caught. The page also leaves out what Veracode actually does for GitHub users: SARIF conversion, check-run annotations and PR comments ([veracode-pipeline-scan-results-to-sarif](https://github.com/veracode/veracode-pipeline-scan-results-to-sarif); [GitHub Workflow Integration](https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning)). For Ascent's design purposes, the right input is Veracode's documentation, not this page.

## Part 2 — Ascent's critical gap is the missing verdict, not missing scanners

### How Veracode's gating really works

Veracode has two disconnected gates. The **platform policy gate** evaluates Upload-and-Scan results against a policy assigned to the application profile. It fails the build only when the state is Did Not Pass, which happens when required scans are missing, the target level is not met, or flaws have outlived their grace period. A **Conditional Pass** covers flaws still inside their grace window, and every sandbox scan receives that status ([Application security policies](https://docs.veracode.com/r/c_appsec_policies)). The **fast gate** is Pipeline Scan. It applies local severity or CWE criteria, optionally against a baseline file. Its exit code is the flaw count (1–200, capped), with −1/255 for errors. The Veracode CLI wrapper returns 3 when flaws match ([Pipeline Scan parameters](https://docs.veracode.com/r/Pipeline_Scan_parameters); [veracode static scan](https://docs.veracode.com/r/veracode_static_scan)). A third surface, the IDE, does not feed the governed lifecycle at all ([VS Code doc](https://docs.veracode.com/r/Veracode_Scan_for_VS_Code)).

Veracode's "fix verification" is **differential status by heuristic matching**, not a re-test. A flaw is marked Fixed when a matched flaw is absent from the current scan. Matching requires an unchanged source file name and module name, so renamed files and dense flaw clusters can produce a false Fixed + New pair. When that happens, the approved mitigation is silently lost ([Matching flaws between scans](https://docs.veracode.com/r/Matching_flaws_between_scans)). Mitigations go through a two-role workflow. A Reviewer proposes one of six actions with a mandatory comment, and a Mitigation Approver accepts or rejects it. The flaw keeps counting against policy until it is accepted, and comments cannot be deleted once a decision is made. Veracode documents no separate audit log ([Propose mitigations](https://docs.veracode.com/r/Propose_mitigations_for_flaws); [Accept and reject mitigations](https://docs.veracode.com/r/Accept_and_reject_mitigations)).

### Gap matrix

| Veracode feature (as it really works) | Ascent today | Gap | Recommended open-standard approach |
|---|---|---|---|
| **Policy-based scanning.** Platform/API policy objects assigned to app profiles, with single-criterion rules (severity, CWE ID/category, scan type, minimum score, standard, SCA license/blocklist/CVSS) and four compliance states ([policies](https://docs.veracode.com/r/c_appsec_policies); [rules](https://docs.veracode.com/r/General_security_policy_rules)) | No pass/warn/fail evaluation. Output is `out/queue.json` and `out/report.md` (Ascent source code, src/pipeline.rs, src/report.rs) | **Critical** | A versioned `ascent-policy.yaml` in the repo, evaluated over every category. Optional Rego via Conftest's `deny`/`warn`/`exception` model ([Conftest](https://www.conftest.dev/)). PASS / CONDITIONAL / FAIL recorded in `gate.json` |
| **Fail-the-build.** Pipeline Scan exits 0, 1–200 (flaw count) or −1/255. The CLI exits 3. `failBuildOnPolicyFail` on `Veracode@3` ([parameters](https://docs.veracode.com/r/Pipeline_Scan_parameters); [ADO](https://docs.veracode.com/r/Azure_DevOps_Extension)) | A successful run always exits 0 | **Critical** | Exit contract: 0 pass, 1 policy fail, 2 config error, 3 incomplete scan, 4 integrity/scope failure. Follows semgrep and Conftest conventions ([Semgrep CLI](https://docs.semgrep.dev/cli-reference); [Conftest options](https://www.conftest.dev/options/)) |
| **Baseline / new-only.** `--baseline_file` is a prior `results.json`. Findings in it are filtered out ([parameters](https://docs.veracode.com/r/Pipeline_Scan_parameters)) | `queue.json` is reset every run. No delta | **High** | SARIF `baselineState` (new/unchanged/updated/absent) over a versioned `ascent/v1` fingerprint ([OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)) |
| **Fix verification / flaw lifecycle.** New/Open/Reopened/Fixed by heuristic match. "Fixed" means absent from the rescan ([Results page](https://docs.veracode.com/r/Access_results_in_the_Veracode_Platform)) | Targeted, human-gated, hash-bound nuclei re-test of a specific finding (Ascent source code, src/exploit/propose.rs, src/exploit/execute.rs). No cross-run lifecycle | **High** for the lifecycle. **Ahead** on re-test | Two-tier status: `absent` (not seen in a *complete* rescan) and `verified_fixed` (an approved targeted re-test came back negative). Baseline-only findings from a failed or narrowed scan become `not_rescanned`, never fixed |
| **Mitigations.** Six actions, proposer/approver separation, mandatory comments, immutable once decided, carried forward only on a match ([mitigations](https://docs.veracode.com/r/Propose_mitigations_for_flaws)) | None at finding level. Crux verdicts are advisory (Ascent source code, src/triage.rs) | **High** | A waiver file with **mandatory expiry**, approved through the existing dashboard gate flow and chained into `audit.jsonl`. Exported as SARIF `suppressions[{kind: external, status}]` |
| **Grace periods.** Per-severity or CVSS-range windows from first-found or reopened date. Zero means immediate failure ([grace periods](https://docs.veracode.com/r/c_policy_grace_period)) | None | **Medium** | `grace_days` per severity keyed on `first_seen`, following DefectDojo's SLA model ([DefectDojo SLA](https://docs.defectdojo.com/asset_modelling/os_hierarchy/os__sla_configuration/)) |
| **SCA vulnerabilities.** CVSS mapped to Veracode severity using NVD-style bands. The update advisor recommends the next safe version ([severity](https://docs.veracode.com/r/review_severity_exploitability)) | `trivy fs` vulnerabilities, but the normaliser drops `FixedVersion` and `InstalledVersion` (Ascent source code, src/normalise.rs) | **Medium** | Capture `FixedVersion`, `InstalledVersion`, `PkgIdentifier.PURL` and `CVSS` from trivy JSON ([Trivy reporting](https://trivy.dev/latest/docs/configuration/reporting/)) |
| **SCA license compliance.** Risk ratings High/Medium/Low/Non-OSS/Unrecognized. `LICENSE_RISK` and Component Licenses rules ([license risk](https://docs.veracode.com/r/c_integrated_license_agent); [Policy API](https://docs.veracode.com/r/Policy_API_Rules_Properties)) | None | **Medium** | `trivy --scanners license`, SPDX IDs, policy `deny`/`warn` lists ([Trivy license](https://trivy.dev/latest/docs/scanner/license/)) |
| **SCA auto-remediation PRs.** srcclr agent with `--update-advisor --pull-request`, `pr_on`, `no_breaking_updates`. No Yarn support. Fix for SCA in SCM is triggered by a PR comment and licensed separately ([Automatic PRs](https://docs.veracode.com/r/About_Automatic_Pull_Requests); [GitHub Workflow Integration](https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning)) | None | **Non-goal (deferred)** | Report the minimal fixed version as remediation text and leave PR creation to the team's existing dependency-update tooling |
| **Veracode Fix (AI patches).** SAST and SCA via IDE, CLI and SCM. It generates patches but does not verify them; the docs advise rebuilding and rescanning ([About Veracode Fix](https://docs.veracode.com/r/About_Veracode_Fix)) | Crux writes advisory remediation text | **Non-goal** | Keep remediation advisory. A human writes the change, and Ascent's re-test verifies it |
| **Container scanning.** `veracode scan --type image\|directory\|repo\|archive`, Syft JSON or CycloneDX 1.6, Rego policies, secrets and IaC. No malware scanning ([veracode scan](https://docs.veracode.com/r/veracode_scan)) | None | **Medium** | `trivy image`, scoped by digest, preferring `--input <tar>` or local sources, with `--offline-scan` when air-gapped ([Trivy image target](https://trivy.dev/latest/docs/target/container_image/)) |
| **DAST.** Dynamic Analysis: authenticated and unauthenticated scans, Selenium crawl scripts, internal scanning. DAST Essentials: three auth modes and replayable payloads ([Dynamic Analysis](https://docs.veracode.com/r/Dynamic_Analysis); [DAST Essentials](https://www.veracode.com/blog/intro-appsec/getting-started-guide-veracode-dast-essentials)) | nuclei with httpx/katana recon behind ScopeGuard (Ascent source code, src/stages/scan.rs). Authenticated scanning is not among current capabilities | **Low** | Keep nuclei. Emit DAST evidence as SARIF `webRequest`/`webResponse` in a separate file |
| **SARIF / GitHub surfacing.** Not native. A converter action turns `results.json` into SARIF, and the GitHub Workflow Integration adds check runs, PR comments and issues ([SARIF converter](https://github.com/veracode/veracode-pipeline-scan-results-to-sarif)) | None | **High** | Native SARIF 2.1.0 emitter, one run per category, uploaded with `upload-sarif` ([GitHub SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)) |
| **IDE integration.** Veracode Scan for VS Code, JetBrains, Visual Studio and Eclipse. Cloud scans run on demand, rate-limited to 6 per minute, and results stay in the IDE ([VS Code doc](https://docs.veracode.com/r/Veracode_Scan_for_VS_Code)) | None | **Low** | Do not build a plugin. SARIF output reaches editors through any SARIF-capable viewer and through GitHub code scanning |
| **Malicious-package detection.** Phylum technology acquired in January 2025 ([Veracode PR](https://www.veracode.com/press-release/veracode-acquires-phylum-inc-technology-to-transform-software-supply-chain-security/)) | None | **Low (deferred)** | Out of scope for a scan-and-triage pipeline. Revisit once SCA is complete |
| **Audit trail.** Per-flaw comment threads, immutable after a decision. No documented tamper-evident log ([Accept/reject](https://docs.veracode.com/r/Accept_and_reject_mitigations)) | Hash-chained `audit.jsonl`, verified before use, fail closed | **Ascent ahead** | Extend the chain to gate decisions, waivers and status transitions |
| **Scope enforcement.** No equivalent per-request guard appears in the Veracode material reviewed | Fail-closed ScopeGuard on hosts, CIDRs and URLs (Ascent source code, src/scope.rs) | **Ascent ahead** | Extend to image registries and digests |

### Three places Ascent already beats Veracode's design

First, **auditability**. Veracode's mitigation record is a per-flaw comment thread that cannot be deleted after a decision. That is useful, but it is not cryptographically tamper-evident, and nothing in the docs describes an exportable, verifiable log ([Accept and reject mitigations](https://docs.veracode.com/r/Accept_and_reject_mitigations)). Ascent's hash-chained audit log already refuses to execute on a broken chain. Waivers and gate decisions recorded in that log would be stronger evidence for an auditor than anything Veracode documents.

Second, **verification semantics**. Veracode's "Fixed" means "not matched in the latest scan", and its own docs list the ways matching fails ([Matching flaws](https://docs.veracode.com/r/Matching_flaws_between_scans)). Veracode Fix produces patches but asks developers to rebuild and rescan to confirm them ([About Veracode Fix](https://docs.veracode.com/r/About_Veracode_Fix)). Even Veracode's DAST "validation" is a payload the user replays with curl ([DAST Essentials](https://www.veracode.com/blog/intro-appsec/getting-started-guide-veracode-dast-essentials)). Ascent's approved, scope-checked, hash-bound re-test of one specific finding is a stronger signal. The roadmap below keeps that distinction explicit instead of collapsing it into a single "fixed" flag.

Third, **scope**. Every network target in Ascent passes a fail-closed guard. For a tool that performs active verification, that guard is the safety case, and none of the Veracode material reviewed describes an equivalent.

One counter-argument deserves weight. Veracode's matching runs on a program-logic and data-flow model, so its flaw identity can survive line shifts better than a naive file-and-line key ([Matching flaws](https://docs.veracode.com/r/Matching_flaws_between_scans)). Ascent's fingerprint must clear that bar, which is why the recipe below hashes normalised code context rather than line numbers.

## Part 3 — A four-milestone roadmap that starts with exit codes

The order follows dependencies and user impact. A CI consumer notices the gate first. The gate's `new_only` and grace logic need a stable fingerprint and `first_seen`. Waivers attach to fingerprints. SARIF needs both fingerprints and suppressions. New scanners (license, image) should land last, after the policy and output layers they will feed exist.

### Milestone 1 — The gate: fingerprint v1, policy, exit codes

Build this first because it closes both Critical gaps and makes Ascent usable as a CI step. Run the subprocess scanners so that **only Ascent's policy engine decides the CI result**. Gitleaks returns 1 for both leaks and errors, so run it with `--exit-code 0` and read the JSON ([gitleaks README](https://github.com/gitleaks/gitleaks)). Leave trivy's `--exit-code` at its default of 0, and do not pass `--error` to opengrep. Opengrep's exit codes are assumed to match semgrep's, but this has not been verified ([Semgrep CLI](https://docs.semgrep.dev/cli-reference)). In the same milestone, enrich the trivy normaliser with `FixedVersion`, `InstalledVersion`, PURL and CVSS. It costs little and feeds the fingerprint, the remediation text and the `updated` state ([Trivy reporting](https://trivy.dev/latest/docs/configuration/reporting/)).

**Exit-code contract** (follows semgrep's and Conftest's 0/1/2 pattern; codes 3 and 4 are Ascent's own fail-closed additions):

| Code | Meaning | Notes |
|---|---|---|
| 0 | Policy PASS or CONDITIONAL | Warnings and in-grace findings allowed |
| 1 | Policy FAIL | At least one in-threshold finding that is not waived and is out of grace. `--fail-on-warn` also returns 1 on warnings, as Conftest does ([Conftest options](https://www.conftest.dev/options/)) |
| 2 | Usage, config or policy-parse error | Malformed policy fails closed, as semgrep returns 5 for an invalid config ([Semgrep CLI](https://docs.semgrep.dev/cli-reference)) |
| 3 | Scanner failed or timed out | Results incomplete. No baseline-only finding may be reported as fixed |
| 4 | Scope violation or broken audit chain | Consistent with the existing refuse-on-broken-chain behaviour |

**Policy schema** (`ascent-policy.yaml`, adapted from trivy, Veracode Pipeline Scan, Conftest and DefectDojo patterns; [Trivy filtering](https://trivy.dev/latest/docs/configuration/filtering/); [Pipeline Scan parameters](https://docs.veracode.com/r/Pipeline_Scan_parameters)):

```yaml
version: 1
name: default
fail_on:
  severity: [CRITICAL, HIGH]          # cf. --fail_on_severity
  categories: [SAST, SCA, SECRETS, DAST, LICENSE, IMAGE]
  cwe: []                             # optional, cf. --fail_on_cwe
  new_only: false                     # true = evaluate baselineState=new only (Milestone 2)
warn_on:
  severity: [MEDIUM]
triage:
  likely_false_positive: demote_to_warn   # never silently pass; a human waiver removes it
grace_days: { CRITICAL: 0, HIGH: 7, MEDIUM: 30, LOW: 90 }   # Milestone 2; 0 = immediate
license:                              # Milestone 4
  deny: [AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0]
  warn: [GPL-2.0-only, GPL-3.0-only, LGPL-2.1-only, MPL-2.0]
  fail_on_unknown: false
waivers:
  file: .ascent/waivers.yaml
  max_days: 180                       # longer expiry is rejected (exit 2)
```

Two choices here depart from the research notes. The notes let LIKELY_FALSE_POSITIVE findings never fail the build. For a human-in-the-loop tool, an offline triage engine should not silently clear a gate. **A likely-FP verdict should demote fail to warn, and only a human-approved waiver should remove the finding.** The gate outcome should also mirror Veracode's three useful states. Ascent's PASS, CONDITIONAL (only in-grace or warn findings) and FAIL map onto Passed, Conditional Pass and Did Not Pass, which gives Veracode users a familiar vocabulary ([Application security policies](https://docs.veracode.com/r/c_appsec_policies)). Write a `gate.json` beside `report.md` containing the policy name and hash, counts by severity and by `baselineState`, the waived and graced counts, the decision and the exit code. Chain its hash into `audit.jsonl`, and show it read-only on the dashboard Overview. The dashboard displays results; it never launches runs.

**Fingerprint recipe** (`ascent/v1`, after CodeQL's line-shift-tolerant hashing; [codeql-action fingerprints.ts](https://raw.githubusercontent.com/github/codeql-action/main/src/fingerprints.ts)):

| Category | Fingerprint inputs (sha256, `‖` = separator) | Deliberately excluded |
|---|---|---|
| SAST | rule_id ‖ normalised repo-relative path ‖ hash of the 100-significant-character window from the result line ‖ occurrence index | Line number, title |
| Secrets | rule_id ‖ path ‖ sha256(secret value) | Raw secret, commit, line. A rotated secret correctly shows as fixed plus new |
| SCA / image | vuln_id ‖ PURL without version ‖ manifest path or target class | Installed version, image digest/tag, so an upgrade that still carries the CVE persists |
| License | SPDX ID ‖ package name or file path | — |
| DAST | template ID ‖ scheme+host+port ‖ path template (numeric/UUID segments stripped, query *names* sorted, values dropped) ‖ method ‖ parameter name | Query values, session tokens |

Prefix every value with its version (`ascent/v1:`), following SARIF's `/vN` convention, so the algorithm can change without orphaning history ([OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)). Audit Ascent's current de-duplication key in src/triage.rs. If it depends on line numbers, freeze it as `ascent/v0`.

### Milestone 2 — Memory: baselines, fix status, waivers, grace

Add a small state store keyed by fingerprint that records `first_seen`, `last_seen`, `fixed_at`, `verified_fixed_at` and run IDs. Compute the delta against the previous complete run, or against a pinned `--baseline` file, which mirrors Veracode's `--baseline_file` ([Pipeline Scan parameters](https://docs.veracode.com/r/Pipeline_Scan_parameters)).

| State | Rule | SARIF `baselineState` |
|---|---|---|
| new | Fingerprint only in the current run | `new` |
| unchanged | In both runs, no material change | `unchanged` |
| updated | In both runs; severity, verdict, fixed version or line changed | `updated` |
| absent (fixed) | Only in the baseline, and the same scanner set completed on the same scope | `absent` |
| not_rescanned | Only in the baseline, but a scanner errored or the scope shrank | omitted; exit 3 if gating depends on it |
| verified_fixed | `absent`, plus an approved targeted re-test came back negative | `absent` + `properties.ascent.verified` |

This is where Ascent outdoes Veracode's lifecycle. `absent` is Veracode-equivalent. `verified_fixed` is stronger, because it reuses the existing hash-bound approval gate. Extending the targeted re-test beyond DAST, for example by re-running only the originating SAST rule against the affected file, is a natural follow-on.

**Waiver schema** (`.ascent/waivers.yaml`). The `kind` values carry over Veracode's six mitigation actions ([Propose mitigations](https://docs.veracode.com/r/Propose_mitigations_for_flaws)). The `status` values map to SARIF `suppression.status` ([OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)). Expiry is mandatory, unlike trivy's optional `exp:` ([Trivy filtering](https://trivy.dev/latest/docs/configuration/filtering/)):

```yaml
version: 1
waivers:
  - id: W-0007
    fingerprint: "ascent/v1:9f2c..."      # or rule_id + paths for a scoped rule waiver
    rule_id: opengrep.python.sqli
    paths: ["legacy/**"]
    kind: mitigated_by_design             # mitigated_by_design | mitigated_by_network |
                                          # mitigated_by_os | false_positive |
                                          # reported_upstream | accepted_risk
    status: accepted                      # proposed | accepted | rejected  -> SARIF underReview/accepted/rejected
    justification: "Input is server-generated; see TICKET-123"
    proposed_by: alice
    approved_by: dennis                   # must differ from proposed_by
    approved_at: 2026-10-30
    expires: 2027-01-31                   # required; <= policy waivers.max_days
    audit_ref: "sha256:..."               # audit.jsonl entry that recorded the approval
```

Mandatory expiry is not bureaucracy. Veracode itself warns that environment changes or new attack techniques can make network and OS mitigations ineffective ([Mitigate vulnerabilities](https://docs.veracode.com/r/Mitigate_vulnerabilities)). Propose and approve waivers through the dashboard's existing gate mechanism, with separate proposer and approver roles as in Veracode. An expired waiver reactivates the finding. Unlike DefectDojo, where an expired risk acceptance can restart the SLA, an expired waiver should not reset the `first_seen` grace clock, so the system fails closed ([DefectDojo SLA](https://docs.defectdojo.com/asset_modelling/os_hierarchy/os__sla_configuration/)). The evaluation order for each finding is: scope filter → waiver (unexpired) → grace (`today − first_seen > grace_days[sev]`) → `fail_on` → `warn_on`. Every waiver hit and expiry is written to `audit.jsonl`.

### Milestone 3 — Interop: native SARIF 2.1.0

Veracode needs a separate converter action to produce SARIF ([SARIF converter](https://github.com/veracode/veracode-pipeline-scan-results-to-sarif)). Ascent should emit it natively. Write one run per category under `automationDetails.id` values such as `ascent/sast/`, staying under GitHub's 20-runs-per-file limit, and write DAST to a separate `ascent-dast.sarif`. GitHub cannot fingerprint `https://` URIs and rejects absolute URIs whose scheme differs from the source root ([GitHub SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)).

| Ascent field | SARIF 2.1.0 location |
|---|---|
| `rule_id` | `result.ruleId` and `tool.driver.rules[].id` |
| `title` | `rules[].shortDescription.text` (≤ 1,024 chars) |
| `message` | `result.message.text` |
| `severity` | `result.level` + `rules[].properties.security-severity` (see below) |
| `cwe` | `rules[].properties.tags` = `["security", "CWE-89", ...]` (max 10 used) |
| `category` | Run split + `automationDetails.id` |
| `file`, `line` | `physicalLocation.artifactLocation.uri` (repo-relative) + `region.startLine/startColumn/endLine/endColumn` |
| `url` (DAST) | Absolute `artifactLocation.uri` (no `uriBaseId`) + `result.webRequest`/`webResponse` |
| `tool` (opengrep/gitleaks/trivy/nuclei) | `result.properties["ascent.tool"]` |
| `evidence` | `result.properties` (secrets already redacted by the normaliser) |
| verdict, confidence, fp_likelihood, rationale, remediation | `result.properties["ascent.*"]` |
| LIKELY_FALSE_POSITIVE | `suppressions[{kind: external, status: underReview, justification}]` |
| Accepted waiver | `suppressions[{kind: external, status: accepted, justification}]` |
| Fingerprint | `partialFingerprints["ascentFindingHash/v1"]` + `primaryLocationLineHash` |
| Delta state | `result.baselineState` |

| Ascent severity | `level` | `security-severity` | GitHub band |
|---|---|---|---|
| CRITICAL | error | 9.5 (or real CVSS for SCA) | critical |
| HIGH | error | 8.0 | high |
| MEDIUM | warning | 5.5 | medium |
| LOW | note | 2.0 | low |
| INFO | note | omitted | none |

GitHub de-duplicates only on `partialFingerprints.primaryLocationLineHash` and warns that REST uploads without it may duplicate alerts ([GitHub SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)). Port CodeQL's roughly 100-line rolling-hash algorithm to Rust: modulus 37, a 100-character window, and a `:n` occurrence suffix ([fingerprints.ts](https://raw.githubusercontent.com/github/codeql-action/main/src/fingerprints.ts)). The midpoint scores avoid GitHub's ambiguous 9.0 boundary. License findings get `["license", "compliance"]` tags and no `security-severity`, so GitHub treats them as non-security results. Uploads use `github/codeql-action/upload-sarif` with `security-events: write` permission ([Uploading SARIF](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github)). This milestone also provides the IDE story, because any SARIF-aware editor or the GitHub PR view can show findings without an Ascent plugin.

### Milestone 4 — Coverage: license and container image scanning

Add `--scanners license` to the existing trivy invocation. Map `Results[].Licenses[]` (`Category`, `Name`, `PkgName`/`FilePath`, `Link`) to a new LICENSE category with `rule_id = license/<category>/<name>`. Normalise names to current SPDX IDs, for example `GPL-2.0` to `GPL-2.0-only`, and treat `MIT OR GPL-2.0` as allowed when any operand is allowed ([Trivy license scanning](https://trivy.dev/latest/docs/scanner/license/); [trivy license.go](https://raw.githubusercontent.com/aquasecurity/trivy/main/pkg/types/license.go)). Trivy's defaults already classify AGPL as forbidden (CRITICAL), GPL and LGPL as restricted (HIGH), and MPL and EPL as reciprocal (MEDIUM). License findings are not exploitable, so they should skip Crux triage. Whether GPL matters depends on how the product is distributed, which is a reason to keep the lists in the policy file rather than hard-coding them.

Add `trivy image` as a scope-governed target type. A scope entry names either a registry/repository pattern or a pinned `sha256:` digest. Before scanning, Ascent resolves the tag to a digest and records the digest in the audit log, then checks the registry host against the scope allow-list, because a pull is network egress. Prefer `--input <tar>` or local `--image-src` sources so locally built images never touch the network, and use `--offline-scan` when air-gapped ([Trivy container image target](https://trivy.dev/latest/docs/target/container_image/)). Image secrets flow into the SECRETS category through the existing redaction path. Do not promise malware scanning. Veracode does not offer it for images either, despite the SecAI page ([Veracode Container Security](https://www.veracode.com/products/container-security/)).

### Deliberately deferred: fix PRs, AI patches, IDE plugins

Automatic fix PRs and AI-generated patches conflict with Ascent's core premise that a human decides and Ascent proves. Veracode's own implementations show the cost. Auto-PRs bump to "the next closest safe version" and can propose major upgrades that teams are told to ignore. They do not support Yarn, and the Fix for SCA variant needs a separate license ([Automatic PRs](https://docs.veracode.com/r/About_Automatic_Pull_Requests); [GitHub Workflow Integration](https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning)). Veracode Fix generates patches but delegates verification to a later rescan ([About Veracode Fix](https://docs.veracode.com/r/About_Veracode_Fix)). Ascent should emit the minimal fixed version and Crux's remediation text, leave the change to a human or an existing dependency bot, and spend its effort on verifying the result. That is where Ascent is already stronger. A dedicated IDE plugin is redundant once SARIF ships. Malicious-package firewalls are a different product category.

## Conclusion

The SecAI page fails in a revealing way. It gets Veracode's broad capabilities right and nearly every operational detail wrong, which suggests that an AppSec product's value lies in its gating semantics, not its scanner list. Ascent already has the harder pieces: credible triage, provable re-testing, scope enforcement and a tamper-evident record. What it lacks is the simplest one, a non-zero exit code backed by a policy, and every other feature parity item depends on a stable fingerprint underneath that policy.

If Ascent builds the gate, memory and SARIF milestones in that order, it ends up with a stricter design than Veracode's, not a copy of it. "Fixed" becomes two states, one of which is proven. Waivers expire by construction and are chained into an audit log. An incomplete rescan fails closed instead of quietly closing findings. Three uncertainties should be tested early: opengrep's exit codes, how well the `ascent/v1` fingerprint survives real refactors compared with Veracode's data-flow matching, and how GitHub treats `security-severity` values at exactly the band boundaries.
