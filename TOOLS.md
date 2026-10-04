# Ascent — Tool Arsenal and License/Gating Matrix

Consolidated from four research passes (Oct 2026). Companion to `PRD.md`. Star counts drift; licenses and status verified against live repos where noted. This is the "all the skills, open-source projects and repos" reference.

## How to read this

- **Consume rule:** the Apache-2.0 orchestrator **shells out to every tool as a subprocess** and parses its output. That keeps even GPL/AGPL tools safe to use. **Never vendor or import copyleft source.**
- **Bundle** = permissive (MIT/Apache/BSD/MPL), safe to ship with the project. **Invoke** = copyleft or restricted, call as an installed binary only, never vendor. **Avoid** = license trap or dead; do not use (or use only on OSS targets / the owner's own license).
- **Gate** = exploit-capable or state-changing; runs detect-only by default, exploit tier requires typed human approval.
- Status: active / lightly maintained / stale / dead.

---

## 1. Recon and subdomain enumeration

| Tool | Repo | License | Status | Role | Class |
|---|---|---|---|---|---|
| subfinder | projectdiscovery/subfinder | MIT | active | passive subdomain enum | Bundle |
| amass | owasp-amass/amass | Apache-2.0 | active | passive+active subdomain, ASN/graph | Bundle |
| dnsx | projectdiscovery/dnsx | MIT | active | DNS resolve/bruteforce | Bundle |
| naabu | projectdiscovery/naabu | MIT | active | fast port scan | Bundle |
| httpx | projectdiscovery/httpx | MIT | active | HTTP probe/fingerprint (backbone) | Bundle |
| gau | lc/gau | MIT | active | URLs from Wayback/CommonCrawl/OTX | Bundle |
| waybackurls | tomnomnom/waybackurls | MIT | light | historical URLs | Bundle |
| cloudlist | projectdiscovery/cloudlist | MIT | active | cloud asset enum (needs creds) | Bundle |
| github-subdomains | gwen001/github-subdomains | MIT | active | subdomains from GitHub (needs token) | Bundle |
| assetfinder | tomnomnom/assetfinder | MIT | light | quick passive subdomains | Bundle |
| findomain | findomain/findomain | GPL-3.0 | active | cert-transparency subdomains | Invoke |
| masscan | robertdavidgraham/masscan | AGPL-3.0 | active | internet-scale port scan | Invoke |
| nmap | nmap/nmap | NPSL (custom) | active | port/service/version + NSE | Invoke |
| rustscan | bee-san/RustScan | GPL-3.0 | active | ultra-fast port scan -> nmap | Invoke |
| shodan / censys CLI | achillean/shodan-python ; censys/censys-python | MIT / Apache-2.0 | active | exposure intel (API key) | Bundle |

## 2. HTTP probe, crawling, content and parameter discovery

| Tool | Repo | License | Status | Role | Class |
|---|---|---|---|---|---|
| httpx | projectdiscovery/httpx | MIT | active | probe/title/tech/TLS/hashes | Bundle |
| webanalyze | rverton/webanalyze | MIT | active | Wappalyzer-style tech fingerprint | Bundle |
| whatweb | urbanadventurer/WhatWeb | GPL-2.0 | light | deep tech fingerprint (1800+ plugins) | Invoke |
| katana | projectdiscovery/katana | MIT | active | JS-aware/headless crawler (best OSS) | Bundle |
| gospider / hakrawler | jaeles-project/gospider ; hakluke/hakrawler | MIT | light | fast crawlers | Bundle |
| ffuf | ffuf/ffuf | MIT | active | dir/file/param/vhost fuzzing | Bundle |
| feroxbuster | epi052/feroxbuster | MIT/Apache | active | recursive content discovery | Bundle |
| dirsearch | maurosoria/dirsearch | GPL-2.0 | active | dir/file brute-force | Invoke |
| gobuster | OJ/gobuster | Apache-2.0 | active | dir/dns/vhost/s3 modes | Bundle |
| x8 | Sh1Yo/x8 | GPL-3.0 | active | hidden parameter discovery (strong) | Invoke |
| arjun | s0md3v/Arjun | AGPL-3.0 | light | HTTP parameter discovery | Invoke |
| paramspider | devanshbatham/ParamSpider | MIT | light | param-URL mining (passive) | Bundle |
| gowitness | sensepost/gowitness | GPL-3.0 | active | headless screenshots (use this) | Invoke |
| aquatone | michenriksen/aquatone | MIT | dead | screenshots (superseded -> gowitness) | Avoid |

## 3. Web vulnerability scanners and DAST platforms

| Tool | Repo | License | Status | Role | Class / note |
|---|---|---|---|---|---|
| nuclei | projectdiscovery/nuclei | MIT | active | template vuln scanner, DAST mode, workflows, OOB | Bundle. **Pin >= v3.10.0 (CVE-2026-76802). Split detection vs intrusive/exploit templates; gate intrusive.** |
| nuclei-templates | projectdiscovery/nuclei-templates | MIT | active | the template corpus (version-pin it) | Bundle |
| OWASP ZAP | zaproxy/zaproxy | Apache-2.0 | active | full DAST proxy+spider+active scan, Automation Framework (YAML), REST API, best OSS authenticated-scan story | Bundle (SARIF via add-on) |
| wapiti | wapiti-scanner/wapiti | GPL-2.0 | active | black-box DAST (SQLi/XSS/LFI/cmdi/SSRF/XXE) | Invoke |
| nikto | sullo/nikto | GPL (custom) | light | server misconfig/known-file (WSTG-CONF) | Invoke |
| Burp Suite Pro | portswigger (proprietary) | paid | active | manual/semi-auto standard; REST API, Montoya extensions | external (not bundled). Key BApps: Autorize, Param Miner, Turbo Intruder, JWT Editor, InQL |
| arachni / w3af / skipfish | — | — | dead | old web scanners | Avoid |

## 4. Injection / payload testing (ALL gated: detect-only by default)

| Tool | Repo | License | Status | Role | Gate |
|---|---|---|---|---|---|
| sqlmap | sqlmapproject/sqlmap | GPL-2.0+ | active | SQLi detect; dump/os-shell/file (gated) | Invoke, **gate dump/shell/write** |
| ghauri | r0oth3x49/ghauri | MIT | active | SQLi detect/exploit (WAF-resilient) | Bundle, gate exploit |
| commix | commixproject/commix | GPL-3.0 | active | OS command injection | Invoke, **gate shell** |
| SSTImap | vladko312/SSTImap | GPL-3.0 | active | SSTI detect/exploit (replaces tplmap) | Invoke, **gate --os-shell/--eval** |
| dalfox | hahwul/dalfox | MIT | active | XSS scanning (preferred for pipelines) | Bundle, detect |
| XSStrike | s0md3v/XSStrike | GPL-3.0 | light | XSS with context/WAF analysis | Invoke |
| interactsh | projectdiscovery/interactsh | MIT | active | OOB capture (blind SSRF/RCE/XXE), self-host | Bundle, confirmation-only |
| ysoserial / ysoserial.net | frohoff/ysoserial ; pwntester/ysoserial.net | MIT | active | Java/.NET deserialization payload gen | Bundle, **gate delivery** |
| XXEinjector | enjoiz/XXEinjector | MIT | stable | XXE file-read/OOB | Bundle, gate |
| Corsy | s0md3v/Corsy | MIT | light | CORS misconfig | Bundle, detect |
| subzy / subjack | PentestPad/subzy ; haccer/subjack | GPL-3.0 / MIT | active / light | subdomain takeover (subzy preferred) | Invoke / Bundle |
| smuggler | defparam/smuggler | MIT | light | HTTP request smuggling detection | Bundle |
| tplmap | epinna/tplmap | GPL-3.0 | dead | SSTI (use SSTImap) | Avoid |

## 5. API testing

| Tool | Repo | License | Status | Role | Class |
|---|---|---|---|---|---|
| Akto | akto-api-security/akto | MIT (core) | active | API discovery + OWASP API Top 10 (BOLA/BFLA/auth) | Bundle |
| schemathesis | schemathesis/schemathesis | MIT | active | property-based OpenAPI/GraphQL fuzzing | Bundle |
| RESTler | microsoft/restler-fuzzer | MIT | active | stateful REST API fuzzing from OpenAPI | Bundle |
| Kiterunner | assetnote/kiterunner | AGPL-3.0 | light | API route discovery from Swagger corpora | Invoke |
| mitmproxy | mitmproxy/mitmproxy | MIT | active | intercept/replay; capture auth, build corpora | Bundle |
| InQL | doyensec/inql | Apache-2.0 | active | GraphQL introspection/schema recovery | Bundle |
| clairvoyance | nikitastupin/clairvoyance | MIT (fork Apache) | active | recover GraphQL schema w/ introspection off | Bundle |
| graphw00f | dolevf/graphw00f | GPL-3.0 | active | fingerprint GraphQL engine | Invoke |
| graphql-cop | dolevf/graphql-cop | MIT | stale | GraphQL misconfig audit | Bundle |
| newman (Postman) | postmanlabs/newman | Apache-2.0 | active | run Postman collections in CI (authed flows) | Bundle |

## 6. Authentication / session / authorization

| Tool | Repo | License | Status | Role | Gate |
|---|---|---|---|---|---|
| jwt_tool | ticarpi/jwt_tool | MIT | active | JWT attacks (alg=none, key confusion, kid, crack) | Bundle |
| Autorize (Burp) | Quitten/Autorize | MIT | active | authz testing (BOLA/IDOR/BFLA) via 2 sessions | Bundle (Burp ext) |
| hydra | vanhauser-thc/thc-hydra | AGPL-3.0 | active | online credential brute/spray | Invoke, **hard-gate (lockout/DoS); test accounts, rate limit, approval** |
| medusa | jmk-foofus/medusa | GPL-2.0 | light | parallel login brute | Invoke, hard-gate |
| enum4linux-ng | cddmp/enum4linux-ng | GPL-3.0 | active | SMB/LDAP/RPC enum (web->host) | Invoke, read-only; gate spray-adjacent |

## 7. TLS / crypto configuration

| Tool | Repo | License | Status | Role | Class |
|---|---|---|---|---|---|
| testssl.sh | testssl/testssl.sh | GPL-2.0 | active | protocols/ciphers/cert/known CVEs | Invoke |
| sslyze | nabla-c0d3/sslyze | AGPL-3.0 | active | fast TLS config scan, JSON (pipeline) | Invoke |
| sslscan | rbsec/sslscan | GPL-3.0 | active | quick cipher/protocol enum | Invoke |

## 8. CMS enumeration

| Tool | Repo | License | Status | Role | Class |
|---|---|---|---|---|---|
| WPScan | wpscanteam/wpscan | dual non-commercial/paid | active | WordPress enum + vuln DB | **Invoke; license-flag: commercial SaaS/resale needs paid licence + API token** |
| joomscan (OWASP) | OWASP/joomscan | GPL-3.0 | stable | Joomla enum | Invoke |
| CMSeeK | Tuhinshubhra/CMSeeK | GPL-3.0 | active | 180+ CMS detection/enum | Invoke (use detection modes; gate exploit modules) |
| droopescan | SamJoan/droopescan | AGPL-3.0 | stale | Drupal/SilverStripe enum | Invoke |

## 9. Exploitation frameworks (gated)

| Tool | Repo | License | Status | Role | Gate |
|---|---|---|---|---|---|
| Metasploit Framework | rapid7/metasploit-framework | BSD-3 (modules vary) | active | module library + RPC API | Invoke. Auxiliary/scanner ~ detect-ok; **never auto-run exploit/* modules, propose only** |
| searchsploit / Exploit-DB | gitlab exploit-database/exploitdb | GPL-2.0 | active | offline exploit search index | Invoke (advisory; surfaces runnable code) |

## 10. Post-exploitation (bounded to authorised impact-demonstration)

Read-only / enumeration only; AI advises, human runs on the host.

| Tool | Repo | License | Status | Role | Class |
|---|---|---|---|---|---|
| LinPEAS / WinPEAS (PEASS-ng) | peass-ng/PEASS-ng | GPL-2.0+ | active | local privesc *enumeration* from a foothold | Invoke, human-run |
| linux-smart-enumeration | diego-treitos/linux-smart-enumeration | GPL-3.0 | active | leveled Linux enum (quieter) | Invoke, human-run |
| Prowler | prowler-cloud/prowler | Apache-2.0 | active | read-only AWS/Azure/GCP/k8s checks (blast radius) | Bundle, read-only |
| ScoutSuite | nccgroup/ScoutSuite | GPL-2.0 | active | read-only multi-cloud posture audit | Invoke, read-only |
| Pacu | RhinoSecurityLabs/pacu | BSD-3 | active | AWS post-ex: enum modules only | Invoke, **enum-only; exclude mutating/privesc modules** |

**Deliberately EXCLUDED from automation** (studied only to exclude): Sliver/Mythic/Havoc/Cobalt-Strike-class C2; NetExec/Impacket automated lateral movement; persistence installers; exfiltration automation; autonomous privesc exploitation.

## 11. SAST engines (white-box track)

| Engine | Repo | License | Lang | Taint depth | Class |
|---|---|---|---|---|---|
| Opengrep | opengrep/opengrep | LGPL-2.1 | multi | **inter-procedural taint restored (free)** | Invoke. **Recommended free taint default** |
| Semgrep CE | semgrep/semgrep | LGPL-2.1 | multi | intra-file (cross-fn moved to paid 2024) | Invoke |
| CodeQL | github/codeql | **proprietary engine** | multi | best-in-class dataflow | **Avoid on client code: OSS/research only, or owner's paid GHAS** |
| gosec | securego/gosec | Apache-2.0 | Go | AST + some flow | Bundle |
| bandit | PyCQA/bandit | Apache-2.0 | Python | AST pattern | Bundle |
| Psalm (--taint) | vimeo/psalm | MIT | PHP | built-in taint | Bundle |
| PHPStan | phpstan/phpstan | MIT | PHP | type + security ext | Bundle |
| Find Security Bugs (SpotBugs) | find-sec-bugs/find-sec-bugs | LGPL | Java/JVM | bytecode taint | Invoke |
| Security Code Scan + Roslyn analyzers | security-code-scan/security-code-scan | LGPL-3.0 / MIT | .NET | Roslyn taint | Invoke / Bundle |
| eslint-plugin-security | eslint-community/eslint-plugin-security | Apache-2.0 | JS/TS | pattern (weak taint) | Bundle |
| Brakeman | presidentbeef/brakeman | **CC BY-NC-SA (non-commercial)** | Ruby/Rails | strong Rails taint | **Avoid in commercial pipeline** (use Opengrep Ruby rules) |

## 12. SCA / SBOM / secrets / IaC / cloud / container

| Tool | Repo | License | Covers | Class |
|---|---|---|---|---|
| Trivy | aquasecurity/trivy | Apache-2.0 | SCA, IaC, secrets, images, k8s, SBOM (the swiss-army) | Bundle |
| Grype | anchore/grype | Apache-2.0 | vuln match on images/dirs/SBOMs | Bundle |
| Syft | anchore/syft | Apache-2.0 | SBOM generation (CycloneDX/SPDX) | Bundle |
| OSV-Scanner | google/osv-scanner | Apache-2.0 | lockfile/SBOM vuln scan | Bundle |
| OWASP Dependency-Check | dependency-check/DependencyCheck | Apache-2.0 | NVD SCA (Java/.NET strong) | Bundle |
| cdxgen | CycloneDX/cdxgen | Apache-2.0 | polyglot SBOM generation | Bundle |
| Dependency-Track | DependencyTrack/dependency-track | Apache-2.0 | SBOM ingestion + monitoring (server) | Bundle |
| Gitleaks | gitleaks/gitleaks | MIT | secrets (git history + files) | Bundle |
| TruffleHog | trufflesecurity/trufflehog | AGPL-3.0 | secrets + live credential verification | Invoke |
| detect-secrets | Yelp/detect-secrets | Apache-2.0 | pre-commit baseline | Bundle |
| Checkov | bridgecrewio/checkov | Apache-2.0 | IaC (TF/CFN/k8s/Helm/ARM) | Bundle |
| KICS | Checkmarx/kics | Apache-2.0 | IaC multi-platform | Bundle |
| Prowler | prowler-cloud/prowler | Apache-2.0 | cloud posture (AWS/Azure/GCP/k8s) | Bundle |
| Kubescape | kubescape/kubescape | Apache-2.0 | k8s misconfig/RBAC/image | Bundle |
| kube-bench | aquasecurity/kube-bench | Apache-2.0 | CIS k8s benchmark | Bundle |
| Dockle | goodwithtech/dockle | Apache-2.0 | container image CIS/best-practice | Bundle |
| tfsec | aquasecurity/tfsec | Apache-2.0 | Terraform (**folded into Trivy; use trivy config**) | Avoid (superseded) |

## 13. Orchestration patterns and findings store

| Project | Repo | License | Learn from it |
|---|---|---|---|
| Osmedeus | j3ssie/osmedeus | MIT | workflow-as-data (YAML), distributed master-worker, pluggable modules. Closest permissive model to emulate |
| nuclei workflows | projectdiscovery/nuclei | MIT | conditional/dependent execution (fire B only if A matched) |
| Trickest workflows/CLI | trickest/workflows, trickest/cli | MIT | pipeline-as-DAG (nodes=tools, edges=data), fan-out/in |
| reconFTW | six2dez/reconftw | GPL-3.0 | phase gating + file-based dedup; resumable chains (study, invoke) |
| reNgine-ng | Security-Tools-Alliance/rengine-ng | GPL-3.0 | DB-backed asset/finding correlation across scans; scheduled rescans + diff |
| DefectDojo | DefectDojo/django-DefectDojo | BSD-3 | **findings store: ~180 parsers, dedup (CWE+location), lifecycle, SLA. Do not rebuild it.** Roadmap aggregation hub |

## 14. LLM-assisted security references

| Project | Repo | License | Use |
|---|---|---|---|
| Capital One VulnHunter | capitalone/vulnhunter | Apache-2.0 | **best AI-advisory + human-in-the-loop SAST blueprint** (hunt/fix/verify Claude skills, falsification engine). Build on |
| Vulnhuntr | protectai/vulnhuntr | AGPL-3.0 | input->sink LLM dataflow technique. **Reimplement, do not fork** |
| Nebula | berylliumsec/nebula | BSD-2 | HITL architecture (intent->approval->execution->evidence), local model. Study first |
| hackingBuddyGPT | ipa-lab/hackingBuddyGPT | MIT | minimal LLM-to-tool wiring reference |
| PentestGPT (legacy) | GreyDGL/PentestGPT | MIT | reasoning/generation/parsing split; Ollama |
| MCP for Security | cyproxio/mcp-for-security | MIT (archived) | per-tool MCP server pattern (study, reimplement) |
| **Avoid as references/deps** | — | — | Villager/Cyberspike (malware-linked), HexStrike AI posture (weaponised), CAI/HexStrike typosquat forks |

## 15. Cheat-sheet

- **Bundle-safe core:** ProjectDiscovery suite (subfinder/dnsx/naabu/httpx/katana/nuclei/interactsh, MIT), ffuf/feroxbuster/dalfox/ghauri/gitleaks (MIT), ZAP/Trivy/Grype/Syft/OSV/Checkov/KICS/Prowler/Kubescape/bandit/gosec/Dependency-Check/schemathesis/RESTler/Akto/newman/InQL (Apache/MIT), Pacu (BSD-3, enum-only), Capital One VulnHunter (Apache), DefectDojo (BSD-3).
- **Invoke-only (copyleft, never vendor):** sqlmap/commix/SSTImap/wapiti/dirsearch (GPL), testssl.sh (GPL), masscan/sslyze/TruffleHog/hydra/Kiterunner/arjun/droopescan (AGPL), ScoutSuite (GPL), Opengrep/Semgrep/find-sec-bugs/Security-Code-Scan (LGPL), reconFTW/reNgine (GPL), nmap (NPSL).
- **Avoid (license trap or dead):** CodeQL on client code (proprietary; OSS/GHAS only), Brakeman (non-commercial), WPScan commercial use (paid licence), tfsec (superseded), arachni/w3af/skipfish/tplmap/aquatone (dead).
- **Always gate (exploit-capable):** sqlmap dump/shell, commix, SSTImap shells, Metasploit exploit modules, ysoserial payload delivery, nuclei intrusive templates, hydra/medusa, Pacu mutating modules.
- **Hard safety:** nuclei >= v3.10.0; secrets in a store not on the CLI; dedicated test accounts; rate limits; scope hook on every call.
