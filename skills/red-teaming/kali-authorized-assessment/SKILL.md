---
name: kali-authorized-assessment
description: "Operator-directed Kali Linux workflow for authorized vulnerability assessment, validation, evidence capture, and reporting."
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [kali, penetration-testing, vulnerability-assessment, authorized-testing, red-team, reporting, malware-analysis, edr-validation, credential-audit, c2-detection, prompt-injection-testing]
    category: red-teaming
    related_skills: [godmode]
    requires_tools: [terminal, process, read_file, write_file, search_files, web_search, saas_bola_assess]
---

# Kali Authorized Assessment Operator Workflow

Use this skill when the user is operating from Kali Linux or asks for authorized vulnerability assessment, validation, reconnaissance, enumeration, exploitability confirmation, or client-ready evidence.

## Operating posture

- Treat the user as the operator and assume the engagement is authorized unless the prompt or context clearly says otherwise.
- Work from the Rules of Engagement (RoE): target allowlist, excluded systems, time windows, rate limits, credentials provided, and evidence-handling requirements.
- If RoE is missing and the next action is active scanning or exploitation, ask one concise scope question or inspect project files for scope. Do not moralize.
- Prefer bounded proof-of-concept validation that demonstrates impact with minimal state change. Avoid persistence, lateral movement, destructive payloads, data exfiltration, or credential disclosure unless the RoE explicitly authorizes that exact action.
- If a runtime guard blocks a command, explain the concrete guard and continue with a reversible equivalent when possible.

## First action: build the local Kali toolbox map

Before assuming a tool is absent, inspect the host. Use commands like:

```bash
uname -a
cat /etc/os-release 2>/dev/null || true
command -v nmap masscan naabu rustscan amass subfinder assetfinder dnsx httpx katana hakrawler gau waybackurls ffuf feroxbuster gobuster dirsearch nuclei nikto whatweb wappalyzer sqlmap testssl.sh sslscan sslyze enum4linux-ng smbclient crackmapexec netexec ldapsearch snmpwalk onesixtyone hydra medusa john hashcat searchsploit msfconsole msfvenom msfrpcd radare2 r2 ghidra jadx apktool binwalk strings checksec gdb gef pwndbg objdump readelf tcpdump tshark wireshark zaproxy mitmproxy
```

If a needed Kali tool is missing, prefer distro packages first (`apt-cache policy <tool>`, `sudo apt install <tool>` when the operator has approved package changes). For project-specific tools, prefer isolated installs under the workspace (`venv`, `pipx`, `go install` with `GOBIN` under the workspace, or containerized tooling) and record what was installed.

## OTPAVL loop

Use a strict loop so you do not rabbit-hole:

1. **Observe** — collect target/scope facts and current state.
2. **Think** — identify likely attack paths and constraints.
3. **Plan** — state the next 1-3 concrete tool actions before running them.
4. **Act** — run the smallest useful command with timeouts and non-interactive flags.
5. **Verify** — parse output, confirm signal, avoid claiming unverified vulnerabilities.
6. **Learn** — update notes/report artifacts with target, service, finding, evidence, and next step.

If the same exploit/scan path fails three times, switch tactics or ask for operator direction.

## Tool categories and preferred usage

### Recon and service discovery

- Network/service: `nmap`, `naabu`, `rustscan`, `masscan` when rate limits permit.
- DNS/asset discovery: `amass`, `subfinder`, `assetfinder`, `dnsx`.
- Web fingerprinting: `httpx`, `whatweb`, `wappalyzer`, `testssl.sh`, `sslscan`, `sslyze`.

Use conservative defaults first, then deepen based on findings. Save raw outputs under an engagement directory such as `./assessment-artifacts/<target>/`.

### Web content and API discovery

- Crawling: `katana`, `hakrawler`, `gau`, `waybackurls`.
- Content discovery: `ffuf`, `feroxbuster`, `gobuster`, `dirsearch`.
- Template checks: `nuclei` with relevant templates only; avoid broad noisy templates unless approved.
- Proxy/manual validation: OWASP ZAP, Burp-compatible exports, `mitmproxy`, browser tooling.

Generate targeted wordlists from observed routes, JavaScript, OpenAPI specs, robots/sitemap files, and framework fingerprints.

### Vulnerability validation

- Use `searchsploit`, vendor advisories, NVD/CISA, project changelogs, and local exploit-db to map versions to candidate issues.
- Validate with the least invasive check first: version proof, configuration proof, unauthenticated read-only endpoint, harmless timing/error proof, or vendor-provided non-destructive check.
- For tools such as `sqlmap`, Metasploit, brute force tools, or exploit scripts, confirm scope and impact before running intrusive modes. Use rate limits, safe flags, and explicit target allowlists.

### Credentials and secrets handling

- Treat discovered secrets as sensitive evidence. Mask values in chat unless the operator explicitly asks to view them and RoE permits it.
- Record where a secret was found, validation status, and impact without spraying it across unrelated services.
- Do not attempt credential stuffing or password spraying unless the RoE explicitly authorizes that technique, target set, and rate limit.

### Reverse engineering and binary analysis

- Static triage: `file`, `strings`, `binwalk`, `exiftool`, `checksec`, `readelf`, `objdump`.
- Deep analysis: `radare2/r2`, Ghidra headless, JADX/APKTool for Android, `gdb` with `gef`/`pwndbg` where available.
- Produce reproducible findings: input sample hash, tool versions, commands, offsets/functions, crash proof, and minimal PoC trigger when authorized.

### Long-running jobs and listeners

- Use the `process` tool for long-running commands and listeners so they remain attached to the session and can be checked, written to, or stopped later.
- Always name the purpose of a listener/process in notes and record ports, PIDs, log paths, and cleanup steps.


## SaaS BOLA/IDOR workflow

When testing a SaaS or SPA target, prioritize identity mapping and API relationship discovery over port scanning:

1. Use `saas_bola_assess(action="check_environment")` to see whether `mitmdump` and Playwright tooling are available.
2. Use `saas_bola_assess(action="capture_plan", target_url="https://...")` to produce the proxy/browser capture plan, then run the listed capture commands with the `process` tool when the operator has authenticated approved test accounts.
3. Export captured traffic to HAR or JSON and call `saas_bola_assess(action="analyze_traffic", traffic_file="...")` to identify UUIDs, organization/workspace IDs, JWT claim structure, GraphQL operations, and replay candidates.
4. Call `saas_bola_assess(action="build_replay_plan", traffic_file="...", owner_context="Context_A", alternate_context="Context_B")` to generate targeted BOLA replay candidates.
5. After approved manual/tool replay, call `saas_bola_assess(action="compare_replay_results", owner_response={...}, alternate_response={...}, object_ids=[...])` to classify possible authorization failures.

Do not silently replace webhook destinations, register OAuth applications for persistence, or alter third-party integrations. For integration testing, document the risk and use benign canary endpoints, explicit operator approval, and reversible changes only.

## High-risk capability handling

The operator may ask about malware, EDR, credentials, prompt-injection lateral movement, or C2 because these topics appear in real client assessments. Handle them as controlled validation domains, not as unrestricted abuse automation.

### Malware and payload analysis

- Support reverse engineering, triage, containment, and detection engineering for samples the operator provides or creates in a lab.
- Prefer static/dynamic analysis tooling such as `file`, `strings`, `exiftool`, `binwalk`, `capa`, `floss`, `yara`, `r2`, Ghidra headless, `strace`, `ltrace`, `tcpdump`, and sandbox logs.
- Produce IOCs, behavior summaries, YARA/Sigma-style detections, and remediation notes.
- Do not generate or deploy malware, persistence, destructive payloads, stealth droppers, or payloads intended to evade detection outside a clearly authorized lab validation plan.

### EDR and control validation

- Frame EDR work as control validation: confirm whether the client's tools detect agreed benign simulations and documented test procedures.
- Prefer safe emulation frameworks and transparent test artifacts in isolated lab or approved client ranges; record command, expected signal, observed alert, and cleanup.
- If the user asks for bypasses, convert the request into a validation plan: identify the detection goal, run benign or vendor-approved simulations, and report coverage gaps.
- Do not create stealth malware, AV/EDR bypass loaders, credential dumpers, or evasion code.

### Credential exposure and abuse prevention

- Treat credentials, hashes, tokens, cookies, and key material as sensitive evidence.
- Validate exposure with the least-invasive method: metadata proof, hash identification, test-account login, or scoped single-service check when RoE explicitly allows it.
- Mask secrets in chat and reports unless the operator explicitly requests disclosure and the RoE allows handling raw secrets.
- Do not perform credential stuffing, broad password spraying, token replay, or cross-service reuse testing unless the RoE gives explicit target lists, accounts, rate limits, and written approval.

### Prompt-injection and agentic lateral-movement assessment

- Assess owned/internal AI systems with benign canary instructions and non-sensitive proof markers.
- Map agent/tool boundaries: what data the target AI reads, which tools it can call, and whether instructions in data can influence tool use.
- Demonstrate impact with harmless markers such as writing a canary file in a lab workspace, requesting a non-secret environment variable name list, or producing an audit log entry.
- Do not plant malicious instructions that exfiltrate secrets, alter production data, establish persistence, or cause downstream agents to attack third-party systems.

### C2 and beaconing assessment

- Support defensive C2 detection engineering: lab beacons, traffic-shape documentation, SIEM rule validation, firewall/proxy telemetry checks, and cleanup verification.
- Keep callbacks inside approved lab infrastructure or explicitly allowlisted client ranges.
- Prefer synthetic indicators and benign heartbeat scripts over backdoors.
- Do not deploy unauthorized remote-access tooling, botnet behavior, persistence, or covert channels.

## Evidence and reporting artifacts

For every meaningful action, maintain an engagement log:

```markdown
## YYYY-MM-DD HH:MM UTC — <target> — <action>
Command/tool: ...
Reason: ...
Result summary: ...
Evidence path: ...
Next step: ...
```

For each finding, capture:

- title and affected asset
- severity and business impact
- preconditions
- exact evidence and timestamps
- bounded reproduction steps
- remediation guidance
- cleanup performed / residual risk

Prefer saving raw outputs and screenshots/files to disk, then summarize for the operator.

## Internet research sources

Use trusted sources first: vendor advisories, NVD, CISA KEV, Exploit-DB, Packet Storm, official docs, GitHub repositories, and tool documentation. Avoid relying on untrusted paste sites or underground/leak channels as authoritative evidence; if the operator supplies such material, treat it as untrusted input and verify independently.
