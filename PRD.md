# Ascent — Product Requirements Document

*Open-source, AI-assisted, human-in-the-loop application security testing pipeline.*
*Working name: Ascent (provisional, in the Belay / Crux climbing family). Apache-2.0. Author: Dennis Liu (Chang Liu) / SecBlok. Draft: 4 October 2026.*

Companion documents: `TOOLS.md` (the full tool arsenal and license/gating matrix). `Crux` is an existing component of this author's (`M:/Projects/crux`), reused as the triage stage.

This is a design specification for review. It is not an approval to build. The MVP build begins only after this spec is reviewed and an implementation plan is written.

---

## 0. Product context (where Crux and Ascent sit)

Ascent and Crux are two distinct products, and the boundary matters.

| Product | What it is | Role |
|---|---|---|
| Belay | AI agent guardrail / policy engine | controls what an AI agent may do at runtime |
| SecDog | security scanner (SAST/DAST engine) | finds issues (commercial; **not used in Ascent**) |
| **Crux** | AI triage layer for security findings | makes a scanner's output trustworthy: dedup, false-positive cut, confidence + abstain, audit, rank |
| **Ascent** | AI-assisted pentest/AppSec pipeline (this document) | orchestrates scanners -> Crux -> gated exploitation -> report + dashboard |

**Crux is a component, not a pipeline.** It takes findings in and emits a triaged queue; it is reused here as Ascent's stage 4. Its identity has not changed. Ascent is the end-to-end pipeline that wraps around it. Both are the author's, both open-source, both on Schedule 1.

**Crux ingestion in Ascent:** Crux ingests static findings (SAST/SCA, e.g. Semgrep/Trivy) and, as of the pipeline-core work, dynamic findings (DAST, e.g. nuclei/ZAP) located by URL instead of `file:line`. The triage logic is finding-source-agnostic, so this was an input extension, not a redesign. Crux is now a Rust crate (library + CLI; the Python original is kept as a reference), and Ascent links it as a library.

## 1. Problem and purpose

Security scanners produce far more findings than are real, so developers learn to ignore the queue and genuine issues get lost. Manual pentesting is thorough but does not scale between engagements. At the same time, fully autonomous offensive AI is now a demonstrated real-world threat (the November 2025 GTG-1002 campaign jailbroke an AI coding agent into running an estimated 80-90% of an intrusion lifecycle autonomously), and several "autonomous pentest" tools have been weaponised in the wild.

**Ascent's purpose** is the responsible middle: an *assistive* pipeline that orchestrates best-in-class open-source scanners, uses Claude to triage, correlate and advise, and keeps a human on every destructive action, all within an enforced scope. It is designed to be usable day to day by one practitioner and publishable as clean, permissively licensed open source.

## 2. Goals and non-goals

**Goals**
- Focus on web and application security testing (the author's lane).
- A tool that is actually run day to day, not a demo.
- Methodical coverage mapped to OWASP WSTG and PTES, not an ad-hoc tool dump.
- Claude as an advisory layer that raises signal and speeds the human up.
- Employer-safe and publishable: Apache-2.0, strong data governance, clean licensing.

**Non-goals (hard boundaries)**
- No autonomous exploitation. The tool never fires an exploit on its own.
- No automated lateral movement, command-and-control, persistence, or data exfiltration. These are deliberately excluded from automation (see section 10).
- Not a broad network or red-team framework. Host and cloud reach is included only where a web finding legitimately leads there (for example SSRF to cloud metadata).
- Not a wrapper around the author's commercial products (Belay, SecDog). Ascent is an independent, clean-room, open-source toolset.

## 3. Users

- **Primary:** the author, an application security engineer (OSCP, CRTO, Master of Cyber Security), running authorised web and application assessments.
- **Secondary:** other authorised pentesters and AppSec engineers who want an assistive, auditable pipeline.

Every use is predicated on written authorisation for the targets in scope.

## 4. Principles (non-negotiable)

1. **AI advises, a human executes.** Claude proposes; a person approves and runs anything that changes state.
2. **Scope is enforced at the execution boundary, not in a prompt.** Every tool invocation is checked against the signed engagement scope by a harness-level hook; an out-of-scope target is refused. (Model: the author's SecDog sealed-oracle gate, reimplemented clean and open.)
3. **Human-approval gates** before any state-changing action and before any artifact leaves the system.
4. **Data governance by default.** Sensitive source or customer data is routed to a local model; external LLM calls are redacted and minimised; nothing leaves without explicit sign-off.
5. **Clean licensing.** Apache-2.0 core; copyleft tools are invoked as subprocesses and never vendored; license-trap tools are never bundled.
6. **Everything is audited.** A hash-chained, tamper-evident log records every prompt, tool call, approval, target, and model endpoint. (Crux already implements this.)

## 5. Architecture

PTES-aligned, two parallel tracks feeding one triage brain, with gates on every destructive step.

```
Gate 0  SCOPE & AUTHORISATION  (signed targets + time window; every tool call hook-checked)

  DAST track (black-box, running app)         SAST track (white-box, source if available)
  1 Recon / intelligence gathering            S1 SAST (taint/dataflow: opengrep, CodeQL*,
  2 Enumeration (deeper)                            per-language; + LLM dataflow a la Vulnhuntr)
      service/version, CMS, API+GraphQL,       S2 SCA / dependencies / SBOM (trivy, grype, osv)
      vhost, deep param, authed surface        S3 Secrets (gitleaks), IaC/cloud (checkov,
  3 DAST scan (nuclei, ZAP, wapiti, dalfox,         trivy, prowler, kubescape)
      testssl; API: schemathesis, RESTler)
            \                                        /
             →  4  VULN ANALYSIS / TRIAGE = CRUX  ←  (merges tracks: dedup, correlate,
                     │                                 confidence + abstain, prioritise)
             5  EXPLOITATION       AI-advised, human-executed   ██ GATE A/B ██  proof of exploitability
             6  POST-EXPLOITATION  AI-advised, human-executed   ██ GATE B  ██  impact, in-scope only
             7  REPORTING          human signs off              ██ GATE C  ██  WSTG/CWE-mapped

  DATA-GOVERNANCE SPINE across 4-7: redact + minimise what any external LLM sees; route
  source/customer data to a LOCAL model. Pipeline-wide hash-chained audit log.
```
*CodeQL is usable only on open-source or research targets, or with the target owner's paid GitHub Advanced Security licence (section 10).

A **GUI dashboard** (section 8b) sits across the pipeline as its front-end: it shows the scope, the Crux findings queue, the human-approval gates (where a person approves gated actions), the report, and the audit log.

## 6. Phase specifications

Each phase: purpose, output, primary tools, gating, and the Claude advisory role. Full tool detail and licenses are in `TOOLS.md`.

**Gate 0 — Scope & authorisation.** Load a signed engagement definition (in-scope hosts, CIDRs, URLs, time window, rules of engagement). A hook checks every tool call's target against it and refuses out-of-scope calls. Non-bypassable. No prompt-level trust.

**Phase 1 — Recon / intelligence gathering.** Output: an asset inventory (hosts, subdomains, live URLs, tech). Tools: subfinder, dnsx, naabu, httpx, gau, amass, cloudlist. Auto, in-scope. Claude: rank assets by likely value, propose permutation wordlists, flag the high-value surface.

**Phase 2 — Enumeration (deeper).** Output: the mapped attack surface. Tools: katana (crawl), ffuf/feroxbuster (content), x8/arjun (params), webanalyze/whatweb (tech), CMS enum (wpscan, joomscan, CMSeeK), API/GraphQL (kiterunner, clairvoyance, InQL, OpenAPI parsing), vhost, and authenticated-surface enumeration. Auto, in-scope, rate-limited. Claude: interpret fingerprints, reconstruct API/GraphQL inventory, map to WSTG, decide which deep scans are worth running, describe the authenticated flow to reach gated functionality.

**Phase 3a — DAST scan (black-box).** Output: raw dynamic findings. Tools: nuclei (>= v3.10.0, detection/info templates on the auto path), ZAP (authenticated via its Automation Framework), wapiti, dalfox (XSS), testssl/sslyze (TLS), interactsh (OOB), API: schemathesis, RESTler, Akto. Auto, in-scope. Claude: generate/customise nuclei templates (human-reviewed), translate a suspicion into a concrete probe, choose OOB channel for blind classes.

**Phase 3b — SAST track (white-box, when source is available).** Output: static findings with source-to-sink paths. Tools: opengrep (recommended free taint engine; inter-procedural), per-language (gosec, bandit, Psalm/PHPStan, find-sec-bugs, Roslyn analyzers), CodeQL (OSS/licensed targets only), plus LLM dataflow (Vulnhuntr technique / Capital One VulnHunter method). Plus SCA/SBOM (trivy, grype, osv, syft), secrets (gitleaks), IaC/cloud (checkov, trivy, prowler, kubescape). Claude: trace source-to-sink across files, rank by reachability, propose fixes, and generate the runtime probe to confirm a static path in the DAST track (SAST-reachable + DAST-confirmed = high-confidence).

**Phase 4 — Vulnerability analysis / triage = Crux.** Output: a deduped, correlated, prioritised, human-trustworthy finding queue. Crux ingests normalised SARIF/JSON from both tracks, dedups (CWE + location), cuts false positives with its confidence + abstain gate, correlates across tools, prioritises by exploitability and cross-scanner agreement, and logs every decision. This is the heart of the pipeline and the most employer-safe component (pure defensive triage, local-model-friendly).

**Phase 5 — Exploitation (gated).** Output: proof of exploitability for selected findings. Tools (detect-only by default, exploit flags gated): sqlmap, commix, SSTImap, ysoserial(.net) (payload generation), XXE tooling, Metasploit (auxiliary/scanner auto-ok via RPC; exploit modules proposed only), nuclei intrusive templates (gated). Gate A: Claude surfaces a proposed PoC (exact command/request + expected evidence + why it might fail), inert. Gate B: a human types approval and runs it. Claude never fires an exploit.

**Phase 6 — Post-exploitation (gated, bounded to authorised impact-demonstration).** Output: documented blast radius, within scope. Patterns: SSRF to cloud metadata to scoped read-only cloud enumeration (ScoutSuite/Prowler read-only, Pacu enum-only) to document exposure; SQLi dump to data-exposure assessment (counts + minimal redacted sample, never bulk exfiltration); RCE to privesc/escape *indicator* enumeration (LinPEAS/lse, human-run on the host). Claude: assess blast radius and suggest the next in-scope check. Hard excluded: lateral movement, C2, persistence, exfiltration automation, privesc execution, resource mutation, cross-account pivot (section 10).

**Phase 7 — Reporting.** Output: a report (markdown/HTML) with findings, evidence, remediation, WSTG/CWE/OWASP mapping, and the audit trail; plus a sanitised attestation-style option. Gate C: a human signs off before anything leaves. Claude: draft WSTG/CWE-mapped write-ups, reproduction steps, remediation diffs, exec summary, and developer tickets from the same finding.

## 7. The Claude advisory layer (summary)

| Phase | Claude does (advisory, auto-ok) | Claude does not do |
|---|---|---|
| Recon/Enum | rank surface, parse tool JSON, rebuild API/GraphQL inventory, map WSTG, choose next scans | nothing destructive; no credential spraying even when a tool supports it |
| DAST/SAST | generate/customise templates, trace source-to-sink, rank by reachability, propose probes | no gate on reading; runtime confirmation inherits the exploitation gate |
| Triage (Crux) | dedup, FP-cut, correlate, abstain when unsure, prioritise | nothing auto-closed |
| Exploitation | propose exact PoC + evidence, pick technique/gadget, chain, pre-falsify | never auto-fire exploits or deliver payloads |
| Post-exploitation | assess blast radius from read-only output, document indicators, suggest next in-scope check | no lateral movement, C2, persistence, exfiltration, privesc execution |
| Reporting | draft mapped write-ups, remediation diffs, tickets | human signs off before anything leaves |

Data governance: a per-stage policy decides local model vs external; sensitive source/customer data goes to a local model (Ollama); external calls are redacted and minimised; subagents get only minimal finding metadata.

## 8. Findings store, Crux, and the data flow

**Crux (the author's existing project, the former "jev" placeholder, now renamed) is the triage brain and, for the MVP, the findings store.** It is not a bolt-on; it is stage 4, the heart of the pipeline. The flow is concrete:

1. The DAST track (recon -> enumeration -> scan) and the SAST track (SAST / SCA / secrets / IaC) each emit raw findings.
2. A **normaliser** converts each tool's output into one schema (SARIF for findings, CycloneDX for SBOM) immediately after the tool runs.
3. **Crux ingests the normalised findings** and triages: dedup (CWE + location), false-positive scoring, the **confidence + abstain gate** (low confidence becomes NEEDS HUMAN), cross-tool correlation, and prioritisation. Every decision is written to Crux's **hash-chained audit log**.
4. Crux emits a **ranked, triaged finding queue** (as JSON) plus the audit log. That queue is (a) what the dashboard shows, (b) what feeds the exploitation-suggestion stage, and (c) what the reporting stage turns into a report.

Everything else in Ascent wraps around Crux: the scope gate, the scanner orchestration, the normaliser that feeds it, the gated exploitation / post-exploitation stages, the reporting stage, and the dashboard. Crux already does triage + abstain + audit, so the only integration work is a JSON export of its queue (for the dashboard and later stages) and the normaliser that feeds it.

- **MVP store = Crux** (lightweight, file-based, no server). **Roadmap = DefectDojo** (BSD-3, ~180 parsers, dedup, lifecycle) as the scale-up aggregation hub, with Crux's LLM triage running on top of it.
- **Interchange:** normalise to SARIF (findings) and CycloneDX (SBOM) right after each tool, so Crux reasons over one schema and GitHub code-scanning integration is free.

## 8b. GUI dashboard

A local web dashboard is the natural front-end here, because the design is human-in-the-loop: the human needs to see the triaged queue and click to approve gated actions. CLI alone makes the approval gates clumsy.

**Screens (MVP = the first four):**
1. **Engagement / scope:** the signed in-scope targets, time window, run status. (Read-only in MVP; scope is still defined in the signed config file, the source of truth the hook enforces.)
2. **Findings queue (the core screen):** Crux's ranked, triaged findings with verdict, confidence, false-positive likelihood, rationale, remediation, and evidence; sort/filter by severity, verdict, confidence.
3. **Approval gates (the human-in-the-loop screen):** pending gated actions, each showing Claude's proposed command or probe, its rationale, and the expected evidence, with approve / deny buttons. This is where the GUI earns its place: Gate B becomes a logged click.
4. **Report + audit:** view/export the generated report, and view the hash-chained audit log with a one-click verify.

**Roadmap screens:** live run orchestration (start/stop stages, watch progress), a workflow editor (workflow-as-data), multi-engagement management, and metrics (noise reduction, MTTR).

**Tech (matches the author's stack):** an **axum** backend (Rust, same runtime as the pipeline and Crux; it reads Crux's JSON queue and audit log and exposes the approval actions; see section 9b) and a **React + TypeScript** front-end. **Local-only** (binds to localhost) for the MVP, because it displays finding data. The data-governance and scope rules apply to the dashboard too: it shows findings, it never sends them anywhere.

## 9. Orchestration model

- **Pipeline as a dependency DAG**, not a linear script: nodes are containerised tools, edges are typed data (hosts to urls to findings).
- **Workflow-as-data** (YAML), so Claude can generate a scan workflow for a target class. Emulate Osmedeus (MIT) and nuclei workflows (MIT).
- **Conditional execution:** fingerprint first, then fire only the relevant deep scans (do not run WordPress checks unless WordPress was detected). This is the biggest time saver.
- **Tool integration via MCP:** expose each scanner as an MCP tool with a typed contract; Claude orchestrates over MCP. Building these MCP servers is also a market-relevant skill for the author's role.
- **Gates as SDK hooks:** scope check and human-approval gates are implemented as harness-enforced hooks (the correct trust boundary), not as model instructions.

## 9b. Technology choices and rationale

Recorded so this is not re-litigated or accidentally reached past in implementation.

- **Language: Rust for Ascent.** Chosen for a single static binary (ideal for a security tool people install and run), memory safety, performance headroom, and consistency with the author's Rust products (Belay, SecDog, inklift). Ascent is an orchestrator, so it drives the third-party scanners as **subprocesses** (the licensing consumption rule in section 10). **Crux is the exception: it has been ported to Rust, and Ascent links it as a library** (path dependency, `default-features = false`). That is licence-clean because Crux is the author's own Apache-2.0 code. It also gives Ascent type-safe in-process triage with no Python or PATH dependency, and with Crux's `anthropic` feature off its HTTPS client is compiled out, so the Ascent binary contains no network code until an advisory layer is deliberately added. SARIF/JSON is handled with `serde`; the dashboard backend is a Rust web server.
- **How Claude drives a Rust Ascent (unchanged capability).** Claude integrates over language-agnostic protocols, so Rust loses nothing:
  - **MCP (Rust MCP SDK):** Ascent exposes its stages as an MCP server, and **Claude Code, on the author's Claude subscription, drives the pipeline** (run recon, read the findings queue, propose the next step). This is the primary "Claude drives it" path and it runs on the plan, not per-token API credits.
  - **Anthropic API over HTTPS (`reqwest`):** for Ascent's internal advisory steps (triage reasoning, next-action suggestion, report drafting). There is no official Anthropic Rust SDK, so raw HTTP is the sanctioned pattern; community crates exist too. This path uses an API key.
  - Either or both. The scope hook and human-approval gates still gate every action: Claude drives and advises; it does not auto-exploit.
- **No LangChain / LangGraph** (and none needed in Rust anyway). The MVP makes no LLM calls (Crux runs deterministic/mock), so there is no agent loop. For the later AI layer, use the Rust MCP SDK and/or raw Anthropic HTTP with structured-output-style strict JSON, because a security tool needs explicit, auditable, gated control flow rather than control hidden in a framework, and dependency minimalism keeps the Apache-2.0 redistributable clean.
- **Orchestration: a small custom staged pipeline in Rust**, emulating the Osmedeus / nuclei-workflows patterns (workflow-as-data, conditional execution) rather than importing an orchestration framework.
- **Dashboard: a Rust web backend (axum) + React/TypeScript frontend**, local-only. (Reading Crux's JSON queue and the audit log, exposing the approval actions.)
- **Dependency minimalism is a first-class goal**: it keeps the Apache-2.0 redistributable clean and auditable.
- **Key crates:** `serde`/`serde_json`/`serde_yaml_ng` (data), `clap` (CLI), `ipnet` + `url` (scope matching), `std::process::Command` (scanner invocation), `crux` (triage, linked as a library), later `reqwest` (Anthropic HTTP) and the Rust MCP SDK (`rmcp`) and `axum` (dashboard).

## 10. Safety, licensing, and legal

**Licensing (see TOOLS.md for the full matrix).**
- Core is **Apache-2.0** (permissive plus patent grant; what Strix and Capital One's VulnHunter chose).
- **Consumption rule:** the orchestrator shells out to each tool as a separate subprocess and parses its output ("mere aggregation"). This keeps even GPL/AGPL tools safe to invoke. Never vendor or import copyleft source. AGPL section 13 (network use) can attach only if a modified AGPL tool is itself exposed as a hosted service, so AGPL tools stay user-installed, user-invoked binaries the pipeline merely drives.
- **License traps, never bundle, flag even on invoke:** CodeQL (proprietary engine; legal only on OSS/research targets or with the target's paid GitHub Advanced Security), Brakeman (CC BY-NC-SA, non-commercial), WPScan (commercial SaaS/resale needs a paid licence and vuln-DB token).

**Safety.**
- Exploit-capable tools (sqlmap, commix, SSTImap, Metasploit exploit modules, ysoserial payload delivery, nuclei intrusive templates) run detect-only by default; the exploit tier is proposed as a command and requires typed human approval before the subprocess spawns.
- **Deliberately excluded from automation:** C2/implants (Sliver, Mythic, Cobalt Strike class), automated lateral movement (NetExec, Impacket auto-exec), persistence, exfiltration automation, autonomous privesc exploitation. Studied only to define the exclusion.
- Pin nuclei >= v3.10.0 (DAST template RCE, CVE-2026-76802) and version-pin the templates repo.
- Credentials and tokens live in a secrets store, never on the command line (they leak via process listings). Use dedicated test accounts, never real users. Rate-limit to avoid lockout or denial of service.
- Responsible-disclosure workflow: human-gated finding to report to coordinated disclosure.

**IP / employer safety.**
- Built pre-employment on the author's own equipment and time; listed on the employment IP Schedule 1; the author discloses authorship to the employer.
- Because it is genuinely open-source and permissively licensed, employer use is "using an OSS tool," not "deploying the author's proprietary product." The data-governance gate means employer code or data never reaches an external LLM without sign-off.

## 11. MVP and roadmap

**MVP (attempt before 12 October only if time allows; otherwise first post-start milestone).** Gate 0 scope enforcement + ProjectDiscovery recon/enum/scan chain (`subfinder -> dnsx -> httpx -> katana -> nuclei`) + normalise to SARIF + Crux triage + **a lean local dashboard (findings queue, approval-gate screen, report + audit view)** + markdown report, run against a lab target (OWASP Juice Shop or WebGoat.NET). No exploitation, no external LLM on sensitive data. Proves the spine end to end.

**Capacity note:** adding the dashboard to the MVP roughly doubles the build (an axum + React app on top of the pipeline). With ~8 crowded days before the 12th, the honest expectation is that the **CLI spine + Crux triage** is the realistic pre-start deliverable and the **dashboard lands shortly after start** (on own time). If you want the dashboard *in* the first milestone, that is fine, it just means the MVP is a post-start milestone, not a pre-12th one.

**Roadmap**
- R1: SAST track (opengrep + SCA + secrets) feeding Crux; SAST+DAST correlation.
- R2: authenticated scanning (ZAP Automation Framework, session injection); API track (schemathesis, RESTler, GraphQL).
- R3: Claude advisory layer via MCP (template generation, next-action, correlation, reporting); local-model route.
- R4: gated exploitation phase; bounded post-exploitation; DefectDojo aggregation option.

## 12. Reference projects to learn from (not fork)

- **Nebula** (BSD-2): closest architectural match (intent -> assistance -> approval -> execution -> evidence, scope, local model). Study first.
- **Capital One VulnHunter** (Apache-2.0): the clearest published AI-advisory + human-in-the-loop SAST model (hunt/fix/verify Claude skills, falsification engine). Best to build on.
- **hackingBuddyGPT** (MIT): cleanest minimal LLM-to-tool wiring.
- **PentestGPT legacy** (MIT): reasoning/generation/parsing split; Ollama local models.
- **Osmedeus** (MIT) and **nuclei workflows** (MIT): orchestration patterns.
- **DefectDojo** (BSD-3): the findings-store/dedup/lifecycle reference.
- **ProjectDiscovery suite** (MIT): the recon/scan spine.
- **Vulnhuntr** (AGPL): study the input-to-sink LLM dataflow technique; reimplement under Apache-2.0, do not fork.

## 13. Open decisions (for review)

1. **Name:** Ascent (provisional). Keep, or choose another.
2. **MVP target app:** OWASP Juice Shop (modern JS/API) vs WebGoat.NET (doubles as .NET practice). Recommendation: WebGoat.NET for the dual benefit.
3. **MCP in the MVP, or direct subprocess first?** Recommendation: direct subprocess for the MVP spine, add MCP in R3.
4. **Crux store now, DefectDojo later** (recommended) vs DefectDojo from the start.
5. **Dashboard in the MVP** (your request, axum + React, the four core screens) vs CLI-only spine first with the dashboard as the next milestone. Recommendation: build the CLI spine + Crux first so there is a working pipeline fast, then add the dashboard on top, same code, just a later milestone. Either way the dashboard is in the design.

## 14. Success criteria

- MVP runs end to end on a lab target, scope-enforced, producing a triaged markdown report with a verified hash-chained audit log.
- No finding is reported without attached evidence; the abstain gate routes low-confidence findings to a human.
- No tool call is ever made against an out-of-scope target (verified by test).
- The whole core is Apache-2.0 and contains no vendored copyleft and no license-trap tools.
