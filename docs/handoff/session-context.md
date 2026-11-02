# Session context (planning chat, 2026-11-02)

Everything from the planning conversation that isn't already in the code or the
plan. Read `docs/handoff/README.md` first.

## 1. What was asked, in order

1. "What are the current tools in market like this?" Competitor landscape for
   Aegis (section 2).
2. "Where can I see if my website is vulnerable or not?" Free checking tools
   (section 3).
3. "Research hostedscan.com/dashboard, all features, build the exact UI, working,
   with all features, be creative, take screenshots." Research is in
   `docs/hostedscan-reference/`. Screenshots came from HostedScan's marketing
   pages, because the logged-in dashboard needs an account.
4. "This is what we have made (github.com/noobProgrammer44/aegis), integrate and
   continue." The repo was cloned to `~/Downloads/aegis` and read in full.
5. "Continue with a loop command, don't stop till everything is done, install
   from GitHub." The loop was started, the scanners were installed, and item 1
   began.
6. "Send all data to a new place for Amul so we can continue there." That
   request produced this handoff.

## 2. Market landscape (EASM tools like Aegis)

**Enterprise platforms**, mostly built by acquisition:
- Palo Alto Cortex Xpanse (Expanse)
- Microsoft Defender EASM (RiskIQ)
- CrowdStrike Falcon Surface (Reposify)
- Tenable ASM (Bit Discovery, $45.5M)
- Google / Mandiant ASM
- Qualys EASM
- Rapid7 Surface Command
- IBM Randori

**Specialist EASM vendors:** CyCognito, Censys ASM, IONIX, Attaxion, Detectify,
Intruder, Halo Security, Hadrian, ImmuniWeb Discovery, Outpost24 (Sweepatic),
Patrowl, Edgescan, Bishop Fox Cosmos, Bugcrowd (Informer).

**Security ratings (outside-in score):** SecurityScorecard, BitSight, UpGuard,
RiskRecon.

**Closest match: ProjectDiscovery Cloud.** It uses the same tools Aegis
orchestrates (subfinder, httpx, katana, nuclei).
- Free tier: up to 10 domains.
- Pro: $2,500/yr.

**Open source:** reNgine, Osmedeus, BBOT, SpiderFoot, OWASP Amass. Newer ones add
LLM summaries: HailBytes ASM, SEAMUS, Reconator, OASM.

**Implications for Aegis:**
- The 4-stage pipeline and the AI summary are no longer differentiators. Several
  open-source tools already have both.
- DNS TXT ownership verification (Tier 2) is standard practice. Commercial
  scanners use it too.
- **Suggested differentiator:** the stakeholder outline argues that AI-written
  code is the problem, but no feature targets it. Add a "vibe-code leak" scanner
  that looks for:
  - API keys in public JS bundles
  - exposed source maps and `.env`
  - public Vercel/Netlify preview deployments
  - Firebase/Supabase config in client code

  This is item 5 (`JS_SECRETS`) in the plan.
- **Suggested change:** drop "proxy rotation" from the stakeholder outline. Real
  scanners publish their scanner IPs so targets can allow-list them. Rotating
  proxies reads as evading blocks, which contradicts "responsible scanning".

## 3. Free "is my site vulnerable" checks (for demos and sanity checks)

- **Passive, safe on any site:**
  - securityheaders.com
  - Mozilla HTTP Observatory
  - SSL Labs
  - Sucuri SiteCheck
  - Google Safe Browsing status
  - crt.sh (`%.domain`)
  - Shodan (`hostname:domain`)
  - MXToolbox (SPF/DMARC)
- **Active, own sites only:** Pentest-Tools.com free scan, HostedScan free tier,
  ProjectDiscovery Cloud free tier, Detectify and Intruder trials.
- **Self-run:** OWASP ZAP, nuclei, Nikto, WPScan.
- **Code-side:** `npm audit`, Dependabot, gitleaks.

## 4. Why HostedScan is the model

HostedScan wraps open-source scanners (ZAP, OpenVAS, Nuclei, Nmap, SSLyze) in a
clean dashboard with targets, scheduled scans, a risk lifecycle, health scores and
reports. Aegis already runs the recon. What it lacks is the platform around it:
persistence, a risk lifecycle, scheduling, reports and integrations. The plan copies
HostedScan's information architecture and features, but keeps Aegis's name, logo,
colours and copy. A pixel-for-pixel copy of their branded UI would be a trade-dress
problem, and the stakeholder doc presents Aegis as its own product.

## 5. Working preferences from Kartik (apply to the build)

- Build and review the work directly. Don't hand it to subagents. Do a careful
  self-review before ticking each item.
- Do not publish claude.ai Artifacts. Write local files and give the path.
- Desktop-first back-office UI, colourful severity visuals in the spirit of
  HostedScan's tiles.
- Never push to GitHub, and never take any other outward-facing action, without
  asking first.
- The repo's git author on Kartik's Mac is the global config
  (`Nishant-FactWise`). Check `git config user.name` before committing on another
  machine.

## 6. Tool install status on Kartik's Mac (2026-11-02)

| Tool | Status |
|---|---|
| subfinder, dnsx, httpx, katana, nuclei | installed in `~/go/bin` via `go install` |
| nmap | installed (Homebrew) |
| sslyze | installed (pipx) |
| Juice Shop image | pulled |
| ZAP image (`zaproxy/zap-stable`) | pulled (3.6 GB) |
| Docker | 29.x running |
| Node | 23.11 (repo targets Node 20+, teammate machine on 24) |
