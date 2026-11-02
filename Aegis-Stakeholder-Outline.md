# Aegis — External Attack Surface Assessment Tool
### Stakeholder Outline & Design Document
*(working name — rename as you like)*

---

## 1. Title & One-Liner

**Aegis** — an automated External Attack Surface Management (EASM) tool that takes a single company domain and discovers, maps, and risk-rates everything that company exposes to the internet.

> *Type one domain → get every subdomain, every live host, the software and versions running on each, and a ranked list of security weaknesses — with an AI-written summary for decision-makers.*

---

## 2. Introduction — The Problem It Solves

Organizations no longer know their own attack surface.

AI-assisted development has made it trivial to ship code and spin up new services. The result:

- **More code, more services, more subdomains** — the attack surface expands faster than any team can track.
- **AI reproduces insecure patterns** from its training data: hard-coded secrets, missing input validation, and — critically — **outdated library versions with publicly known vulnerabilities (CVEs)**.
- **Less human security review** ("vibe coding") means flaws ship unnoticed.
- **Forgotten assets** — `staging.`, `old-api.`, `test.` subdomains get deployed and abandoned. Forgotten means unpatched, and unpatched is the easiest way in.

**An attacker's first move is reconnaissance** — mapping an organization's exposed assets before touching anything. Aegis runs that same reconnaissance **for the defenders**, continuously and automatically, so a security team sees its exposure before an attacker does.

Aegis performs **assessment, not exploitation** — it identifies and reports weaknesses by observing public signals and matching detected software versions against public vulnerability databases. It never attacks, exploits, or attempts to break into any system.

---

## 3. Key Features

### Feature 1 — Subdomain & DNS Discovery
**Description:** Given an apex domain (e.g. `example.com`), Aegis enumerates all discoverable subdomains and retrieves their DNS records (A, AAAA, CNAME, MX, NS, TXT).
**Importance:** You cannot secure what you don't know exists. This feature turns one domain into a complete map of the organization's named internet footprint — including the forgotten assets that are the most common entry points. TXT records additionally reveal third-party services in use (email providers, cloud vendors, verification tokens), widening the picture of the organization's dependencies.

### Feature 2 — Live Host Probing
**Description:** Of the (often hundreds of) discovered subdomains, Aegis determines which are actually live on HTTP/HTTPS, capturing status codes, page titles, redirects, response times, and resolved IPs.
**Importance:** It narrows a large list of *names* down to the *reachable* assets that actually represent risk — focusing the assessment on what's genuinely exposed.

### Feature 3 — Technology Fingerprinting & Crawling
**Description:** For each live host, Aegis identifies the technology stack and versions (web server, frameworks, libraries) from HTTP headers, response signatures, and page content, and crawls for sensitive exposed paths (`/.git`, `/.env`, `/admin`, API docs).
**Importance:** This is where vulnerability starts to surface. Knowing a host runs a specific, outdated version is the single highest-signal indicator of risk, because it can be matched directly against known CVEs.

### Feature 4 — Surface Analysis & Risk Scoring
**Description:** Aegis analyses each host for: missing security headers (HSTS, CSP, X-Frame-Options), outdated versions mapped to known CVEs, subdomain-takeover risk (dangling DNS), and TLS/SSL misconfigurations. Findings are scored by severity.
**Importance:** It converts raw technical observations into a **prioritized action list** — "fix these three critical issues first" — which is what a security team and its stakeholders actually need.

### Feature 5 — Authorization & Scope Control
**Description:** A three-tier model governs what the tool is permitted to do against a target (see Section 6).
**Importance:** It is the difference between a professional assessment tool and a liability. It ensures active scanning only runs against assets the user is authorized to test, and it gives stakeholders a defensible, auditable record of authorized use.

### Feature 6 — AI-Powered Reporting
**Description:** The raw findings are passed to a large language model (via OpenRouter) that produces a clear, stakeholder-readable risk narrative — plus an exportable technical report (JSON + dashboard).
**Importance:** It bridges the gap between technical findings and business decisions, so non-security stakeholders can understand and act on the results.

---

## 4. Methodologies Used

### Methodology 1 — Passive vs. Active Reconnaissance
Aegis distinguishes two modes, and makes the distinction explicit in the product:
- **Passive recon:** reads only publicly available data — Certificate Transparency logs, DNS, and public datasets. It **never touches the target**, so it is safe and legal to run against any domain.
- **Active recon:** sends requests to the target (probing, crawling, fingerprinting). This touches the target and therefore requires authorization.

This separation is a core design principle, not an afterthought.

### Methodology 2 — The Four-Stage Pipeline
Each stage narrows and enriches the output of the previous one:
```
1. Discovery (DNS + subdomains)  →  many names
2. Live Host Probing             →  the reachable subset
3. Crawl & Fingerprint           →  tech + versions per host
4. Surface Analysis              →  ranked, scored findings
```

### Methodology 3 — Orchestration of Industry-Standard Scanners
Rather than reinventing proven capabilities, Aegis **orchestrates best-in-class open-source tooling** (the ProjectDiscovery suite — subfinder, httpx, katana, nuclei) and adds its own intelligence layer on top: authorization, correlation, scoring, reporting, and UI. This mirrors how production attack-surface-management platforms are built.

### Methodology 4 — Known-Vulnerability (CVE) Correlation
Detected software versions are matched against public vulnerability databases (NVD/CVE). This is **detection by reference**, not exploitation — Aegis reports *that* a known-vulnerable version is present; it never attempts to use the vulnerability.

### Methodology 5 — Responsible Scanning
All active scanning is rate-limited and concurrency-capped, respects `robots.txt` where applicable, and uses optional proxy rotation to distribute load on authorized high-volume scans. The tool is designed to behave like a well-mannered crawler, never an abusive one.

---

## 5. Architecture & Technology Stack

| Layer | Choice | Role |
|---|---|---|
| Frontend / Dashboard | **Next.js (App Router) + TypeScript + Tailwind + shadcn/ui** | Input, live progress, results visualization, report export |
| Live progress | **Server-Sent Events + TanStack Query** | Stream each stage's results to the UI as they complete |
| Recon engine | **ProjectDiscovery suite (subfinder, httpx, katana, nuclei)** running in **Docker**, orchestrated from a Node service | The four-stage pipeline |
| Passive data sources | **crt.sh** (certificate transparency), DNS, optional Shodan / SecurityTrails | Discovery without touching the target |
| Vulnerability data | **NVD / CVE API** | Version → known-vulnerability mapping |
| AI analysis | **OpenRouter** (multi-model LLM access) | Stakeholder-readable risk narrative |
| Controls | Scope gate, rate limiting, audit log, optional proxy rotation | Responsible, authorized operation |

---

## 6. Authorized Use & Scope (Governance Model)

Aegis enforces a **three-tier authorization model**:

| Tier | Capability | Authorization required | Applies to |
|---|---|---|---|
| **0 — Passive** | Public-data recon only; never touches the target | None (it reads public information) | Any domain |
| **1 — Active, attested** | Live probing, crawling, fingerprinting — rate-limited and polite | User attests authorization; action is logged (audit trail) | Any domain the user is authorized to test |
| **2 — Active, verified** | Deeper active scanning | Domain ownership proven via DNS TXT token or file upload | Assets the user demonstrably controls |

Tier 2 uses the same domain-verification pattern as SSL certificate issuance and platform domain verification — a recognized, trustworthy mechanism. This model keeps the tool powerful and general-purpose while ensuring it is used lawfully and responsibly, and it gives the organization an auditable record of every active scan.

---

## 7. How Each Feature Contributes to the Security Assessment Process

| Feature | Contribution to the assessment |
|---|---|
| Subdomain & DNS Discovery | Establishes the *complete* attack surface — including shadow/forgotten assets |
| Live Host Probing | Focuses effort on what is genuinely reachable and exploitable |
| Fingerprinting & Crawling | Surfaces the outdated versions and exposed paths that represent real risk |
| Surface Analysis & Scoring | Converts findings into a prioritized remediation plan |
| Authorization & Scope | Keeps the assessment lawful, auditable, and professional |
| AI Reporting | Translates technical risk into business-level decisions |

---

## 8. Limitations & Responsible Use

- Aegis **assesses**; it does not exploit, intrude, or run denial-of-service. It reports weaknesses for remediation.
- Active scanning is restricted to **authorized targets** via the governance model in Section 6.
- Findings represent **indicators of risk** (e.g., a known-vulnerable version is present), which should be validated by a security engineer before action.
- Results are a point-in-time snapshot; attack surface changes continuously, so periodic re-scanning is recommended.

---

## 9. Conclusion — The Tool's Value

As AI accelerates how fast organizations ship code and deploy services, the attack surface grows faster than teams can manually track — and a growing share of that surface carries known, fixable vulnerabilities. Aegis gives a security team continuous, automated visibility into its own external exposure: it finds every asset, identifies what's running on it, flags what's weak, ranks it by severity, and explains it in plain language — all within an authorized, auditable framework.

In short: **Aegis lets defenders see their organization exactly as an attacker would — and fix it first.**

---

## 10. References

- OWASP Top 10 — https://owasp.org/www-project-top-ten/
- OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- Certificate Transparency — https://certificate.transparency.dev/
- NVD (National Vulnerability Database) — https://nvd.nist.gov/
- ProjectDiscovery open-source tooling — https://github.com/projectdiscovery
- MITRE CVE — https://cve.mitre.org/
