# Aegis — Build Plan & Claude Code Prompts
*Ordered steps. Paste each prompt into Claude Code in sequence. Build MVP first, polish later.*

---

## Architecture decision (state this to the CTO)

**Node-first pipeline + orchestrate `nuclei` (via Docker) for deep vulnerability detection.**

The production pattern is *"orchestrate proven scanners + add your own intelligence layer."* The judgment call is **which** to orchestrate vs build:
- **Build in Node** (simple, reliable on Windows, you control/understand it): subdomain discovery (crt.sh), DNS, live probing, crawling, fingerprinting, scoring, auth, AI, UI.
- **Orchestrate** (irreplaceable — thousands of community vuln templates): **`nuclei`**, run via Docker in one command.

> This is not a compromise — it's knowing *which wheels not to reinvent*. You orchestrate the one tool you can't match in a day, and build the rest cleanly. If setup goes smoothly, you can additionally orchestrate `subfinder`/`httpx` later.

---

## Scope discipline (this is the skill being graded)

**MVP first — get the WHOLE pipeline working end-to-end on one target before polishing anything:**
`domain in → subdomains → live hosts → fingerprint → findings → AI summary → shown in UI`

Only after that works, polish: nicer dashboard, more data sources, proxy rotation, multiple targets. **A complete thin slice beats ten half-built features.**

---

## Phase 0 — Setup (do this yourself, ~30 min)

1. Install Node 20+ (you have it).
2. Start your local test target:
   ```
   docker run -d -p 3000:3000 bkimminich/juice-shop
   ```
3. Sign up at **openrouter.ai** → create an API key. Keep it for Phase 8.
4. Make sure Docker can run nuclei (you'll use this in Phase 6):
   ```
   docker pull projectdiscovery/nuclei:latest
   ```
5. Create the project folder and open it in your editor + Claude Code.

---

## Phase 1 — Project scaffold + context

**Claude Code prompt:**
> Create a Next.js 15 app (App Router, TypeScript, Tailwind, shadcn/ui) called "aegis". It's an External Attack Surface Assessment tool: a user enters a domain and it runs a 4-stage recon pipeline (1. subdomain+DNS discovery, 2. live host probing, 3. crawl+fingerprint, 4. surface analysis), then shows ranked findings with an AI summary. Set up: a clean folder structure (`/lib/recon/` for the pipeline stages, `/app/api/` for routes, `/types/` for shared types), a `types/recon.ts` with types for Subdomain, LiveHost, Fingerprint, Finding, ScanResult, and a home page with a domain input box and a results area. Also create a `CLAUDE.md` describing this architecture so you have context in future prompts. Don't build the recon logic yet — just the skeleton and types.

---

## Phase 2 — Stage 1: Discovery (subdomains + DNS)

**Claude Code prompt:**
> Implement Stage 1 in `/lib/recon/discovery.ts`. Given an apex domain: (a) query crt.sh's JSON API (`https://crt.sh/?q=%25.DOMAIN&output=json`) to passively collect subdomains, dedupe them; (b) for each subdomain, use Node's built-in `dns` module to resolve A, AAAA, CNAME, MX, NS, and TXT records. Return a list of `{ subdomain, records }`. Handle timeouts and failures gracefully (a subdomain that doesn't resolve is still recorded as "not resolving"). Add an API route `/api/scan/discovery` that takes a domain and returns the results. Keep it passive — do not send any request to the target itself.

---

## Phase 3 — Stage 2: Live host probe

**Claude Code prompt:**
> Implement Stage 2 in `/lib/recon/probe.ts`. Given the resolved subdomains from Stage 1, probe each on both http:// and https:// using fetch with a 5s timeout. Record: final URL (after redirects), HTTP status, page title, `Server` and `X-Powered-By` headers, response time, and content length. Use `p-limit` to cap concurrency at 10 (politeness). Return only hosts that responded. This is the first "active" stage — add a boolean `activeAllowed` guard that must be true to run it (we'll wire the real authorization UI in Phase 7).

---

## Phase 4 — Stage 3: Crawl + fingerprint

**Claude Code prompt:**
> Implement Stage 3 in `/lib/recon/fingerprint.ts`. For each live host: (a) detect technologies and versions using a Wappalyzer-style library (`simple-wappalyzer` or similar) plus parsing of Server/X-Powered-By headers and HTML meta/script tags; (b) do a shallow crawl (1 level) with `cheerio` to collect internal links; (c) check for sensitive exposed paths by requesting `/.git/config`, `/.env`, `/robots.txt`, `/sitemap.xml`, `/admin`, `/swagger`, `/api-docs` and recording which return non-404. Return `{ host, technologies: [{name, version}], exposedPaths: [], links: [] }`. Keep concurrency capped.

---

## Phase 5 — Stage 4a: Passive surface analysis

**Claude Code prompt:**
> Implement `/lib/recon/analysis.ts`. For each live host produce findings for: (a) missing security headers — check for HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options and flag missing ones; (b) TLS issues — flag if the cert is expired or expiring within 14 days (use Node's tls module); (c) exposed paths from Stage 3 (e.g. an accessible `/.git/config` is HIGH severity). Each finding: `{ host, title, severity: LOW|MEDIUM|HIGH|CRITICAL, description, recommendation }`. Return a findings array.

---

## Phase 6 — Stage 4b: Deep vuln detection (nuclei via Docker) + CVE scoring

**Claude Code prompt:**
> Add `/lib/recon/nuclei.ts` that runs nuclei against the list of live hosts by shelling out to Docker: `docker run --rm projectdiscovery/nuclei -u <urls> -json -severity low,medium,high,critical`. Parse the JSON lines into our Finding type (map nuclei's severity + template name + matched CVE into title/severity/description). Merge these with the Phase 5 findings. Then write `/lib/recon/score.ts` that computes an overall risk score per host and for the whole scan (weight CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1) and sorts findings by severity. If nuclei isn't available, the pipeline should still work with just the Phase 5 findings (graceful degradation).

---

## Phase 7 — Authorization model (3-tier gate)

**Claude Code prompt:**
> Build the authorization gate. Tier 0 (passive discovery) runs on any domain with no gate. Before any ACTIVE stage (probe/crawl/fingerprint/nuclei), require the user to either: (Tier 1) tick a checkbox "I am authorized to actively test this domain" — store this attestation with a timestamp in an in-memory audit log and show it in the UI; or (Tier 2) verify domain ownership by displaying a token the user must add as a DNS TXT record `aegis-verify=<token>`, then a "Verify" button that checks via DNS whether the token is present. Active stages are blocked until Tier 1 or Tier 2 is satisfied. Add a visible "Authorized Use" notice.

---

## Phase 8 — AI reporting (OpenRouter)

**Claude Code prompt:**
> Add `/lib/report/ai-summary.ts` that sends the full ScanResult (hosts, tech, findings, scores) to OpenRouter's chat completions API (key from `OPENROUTER_API_KEY` env var, use a cheap capable model). Prompt it to produce: a 3-sentence executive summary, the top 3 risks in plain English with why they matter, and recommended next actions. Add an API route and show this at the top of the results page. Never send secrets or raw credentials to the API — only the finding metadata.

---

## Phase 9 — Dashboard + live progress

**Claude Code prompt:**
> Wire the full pipeline into one `/api/scan` route that runs all stages in order and streams progress via Server-Sent Events (stage started / stage complete / result). On the frontend use TanStack Query / EventSource to show a live progress view: a stepper for the 4 stages, a subdomain count, a live-hosts table, a findings table (sortable by severity, color-coded), the risk score as a headline number, and the AI summary at the top. Make it clean and presentable — this is shown to stakeholders. Add an "Export JSON" button.

---

## Phase 10 — Demo prep (do yourself)

- [ ] Run a full scan against `vulnweb.com` (discovery) + your local Juice Shop (active) end-to-end.
- [ ] Confirm the AI summary generates.
- [ ] Prepare your 2-min narration: the AI-code→surface→flaws problem → the 4 stages → the authorization model → the findings.
- [ ] Have the stakeholder outline open as the "document" deliverable.
- [ ] Be ready to explain, in your own words: passive vs active, why nuclei, the 3-tier auth, and what each stage does. (The CTO will ask "why did you do X?")
- [ ] Line to say: *"I tested the active pipeline only against Acunetix's vulnweb (published for scanner testing) and a local Juice Shop I control — never an unauthorized third party."*

---

## If you run low on time — cut in this order (keep the slice complete)
1. Drop Phase 6 nuclei → keep Phase 5 (headers/TLS/paths) so findings still appear.
2. Drop Tier 2 ownership verification → keep Tier 1 checkbox.
3. Drop the live SSE progress → just show results when done.
**Never** drop: the 4 stages running end-to-end, the auth gate, and the AI summary. That's the demo.

---

## Phase 0 prompt (paste into Claude Code — it runs the setup)

> I'm building "Aegis", an External Attack Surface Assessment tool (Next.js 15, App Router, TypeScript). Set up my dev environment on Windows. Do these and report what succeeded/failed at each step:
> 1. Print the Node version and confirm it's v20+.
> 2. Confirm Docker is running. Then start my local test target: `docker run -d -p 3000:3000 bkimminich/juice-shop`, and pull the scanner: `docker pull projectdiscovery/nuclei:latest`. Verify Juice Shop responds at http://localhost:3000.
> 3. Initialize a Next.js 15 app in the current folder (App Router, TypeScript, Tailwind, ESLint), named "aegis".
> 4. Install dependencies: `p-limit`, `cheerio`, and a maintained Wappalyzer-style tech-detection library.
> 5. Create `.env.local` containing `OPENROUTER_API_KEY=` (leave it empty) and make sure `.env.local` is gitignored.
> 6. Create a `CLAUDE.md` summarizing the architecture: a 4-stage recon pipeline (discovery → live probe → crawl/fingerprint → surface analysis), Node-first with nuclei orchestrated via Docker for deep vuln detection, a 3-tier authorization model, and an OpenRouter AI summary.
> Finally, tell me the ONE thing I must do manually: sign up at openrouter.ai, create an API key, and paste it into `.env.local`.

---

## Stakeholder outline prompt (if you want Claude Code to generate it in the repo)

*(You already have a polished `Aegis-Stakeholder-Outline.md`. Use this only if you want it generated inside the project, e.g. `docs/`.)*

> Create `docs/stakeholder-outline.md` — a detailed, presentation-ready outline for this Security Assessment Tool ("Aegis"), suitable for showing to stakeholders. Make it clear and professional. Use this structure:
> 1. **Title + one-line pitch.**
> 2. **Introduction — the problem:** AI-assisted development ships more code and spins up more services, expanding the attack surface, often with outdated/vulnerable versions and forgotten "shadow" assets. Attackers begin with reconnaissance; this tool runs that same recon for defenders. State clearly that it performs **assessment, not exploitation**.
> 3. **Key Features (6)**, each with description + why it matters: (1) Subdomain & DNS discovery, (2) Live host probing, (3) Tech fingerprinting & crawling, (4) Surface analysis & risk scoring, (5) Authorization & scope control, (6) AI-powered reporting.
> 4. **Methodologies:** passive vs active recon; the 4-stage pipeline; orchestrating industry-standard scanners (nuclei); CVE correlation (detection, not exploitation); responsible rate-limited scanning.
> 5. **Architecture & tech stack** (table): Next.js/TS/Tailwind frontend, Node orchestration, nuclei in Docker, crt.sh + DNS + NVD data sources, OpenRouter for AI.
> 6. **Authorized Use & Scope — a 3-tier model:** Tier 0 passive (any domain, no auth); Tier 1 active, attested (checkbox + audit log); Tier 2 active, verified (domain ownership via a DNS TXT token).
> 7. **How each feature contributes** to the assessment (table).
> 8. **Limitations & responsible use.**
> 9. **Conclusion** — value summary.
> 10. **References** — OWASP, NVD/CVE, Certificate Transparency, ProjectDiscovery.

---

## Phase 7 — Authorization gate (DETAILED — use this version)

> Phase 7 — build the 3-tier authorization model that controls whether ACTIVE recon (live probe, crawl, fingerprint, nuclei) may run against a target. Passive discovery (crt.sh + DNS) is NEVER gated. Key point: the gate is a self-check inside our tool — we never send anything to the target to "get authorized."
>
> Rules:
> - **Tier 0 (passive):** subdomain discovery + DNS lookups run on any domain, no gate.
> - **Active stages must be blocked SERVER-SIDE** (inside the scan API route, not just by hiding UI buttons) until the target is authorized — otherwise someone could call the API directly and bypass it.
> - A target becomes authorized by **Tier 1 OR Tier 2**:
>   - **Tier 1 (attestation):** user ticks "I am authorized to actively test this domain." Record an audit entry `{ domain, method: 'attested', timestamp }` in an audit log (a simple JSON file or in-memory store is fine) and show the audit log in the UI.
>   - **Tier 2 (ownership verification):** generate a random token and show the user the exact DNS record to add: `aegis-verify=<token>`. A "Verify" button calls an API route that does a DNS TXT lookup on the domain (`dns.resolveTxt`) and checks the token is present. If found, mark the domain verified and record `{ domain, method: 'dns-verified', timestamp }`. This unlocks active scanning without the checkbox. (This is the same mechanism Google Search Console / SSL issuance use.)
> - **Localhost / private targets** (`localhost`, `127.0.0.1`, `*.local`, RFC1918 ranges like 192.168.x / 10.x) are auto-authorized — you inherently control your own machine — so skip the gate for them. This makes the Juice Shop demo frictionless.
> - **Enforce in the scan API:** before running any active stage, check the target is authorized (localhost, attested, or DNS-verified). If not, return 403 with a clear message.
> - **UI:** an "Authorized Use" notice; the Tier 1 checkbox; a Tier 2 "Verify ownership" panel (show the token + a copy button + a Verify button + status). Keep the active-scan controls disabled until the target is authorized. Passive discovery stays available regardless.
>
> Keep the audit log simple but real, so the tool can show that every active scan was authorized.
