# Aegis: external attack surface scanner

Aegis finds what a target exposes to the internet, scans it, and tracks the risks
over time. You add the domains, URLs and IP ranges you own, scan them, and get a
health score, a risk list you can triage, and printable reports. It follows
HostedScan's layout and features under Aegis's own name and design.

> **Authorized use only.** Only scan systems you own or have written permission to
> test. Aegis enforces this on the server (see [Authorization](#authorization)).

---

## 1. Quick start

### Prerequisites

| Tool | Why | Check |
|---|---|---|
| Node.js 20+ | runs the app | `node -v` |
| Docker | nuclei and ZAP scanners, Juice Shop test target | `docker --version` |
| Git | | |

### Install and run

```bash
git clone https://github.com/noobProgrammer44/aegis.git
cd aegis
git checkout feat/hostedscan-parity     # the platform branch (main = original single page)
npm install

# A safe, intentionally vulnerable target to practise on (port 3100)
docker run -d -p 3100:3000 --name aegis-juiceshop bkimminich/juice-shop

# Start Aegis on port 3001 (3000 is often taken)
npm run dev -- -p 3001
```

Open **http://localhost:3001**. You land on the Dashboard.

### One-time extras (optional)

```bash
# nuclei templates, so the first nuclei scan has something to run
docker run --rm -v aegis-nuclei:/root projectdiscovery/nuclei:latest -update-templates

# Sample data to explore the UI, kept in data/demo.db (never touches your real data)
npm run seed:demo
AEGIS_DB_PATH=data/demo.db npm run dev -- -p 3001
```

### Your first scan (5 minutes)

1. **Targets** → **Add targets** → enter `localhost:3100` → **Add targets**.
2. **Scans** → **New scan** → tick **Web surface** and **Port scan**, pick the
   target, **Run scan**. Progress updates live.
3. Open the finished scan to see its findings and download the raw results.
4. **Dashboard** now shows the health score and risk counts. **Risks** lists every
   finding.

---

## 2. Using each screen

| Screen | What you do there |
|---|---|
| **Dashboard** | Health score (0 best, 1000 worst, graded A–F), risks by severity, recent scans / risks / discovered domains, most vulnerable target, 30-day trend. Period selector filters the recent lists. |
| **Quick scan** | One-off scan of one host without saving it (Jay's radar UI + Amaan's pipeline): discovery → probe → ports → fingerprint → analysis → optional nuclei. Download a Markdown report. Turn on **Active scan** for anything beyond passive DNS. |
| **Targets** | Add one or many targets (domain, URL, IPv4, `host:port`, CIDR up to /24), tag and label them, see grade and open risks. Click a target for its **Authorization** panel, risks, scans and metadata. **Discovered domains** tab: subdomains found by discovery; **Add as target** in one click. |
| **Scans** | **New scan**: choose scanners, targets and intensity (Polite / Normal / Aggressive). Running scans update live; stop or delete them; open one for skipped targets (with reasons), new / still open / closed counts and raw result files. |
| **Risks** | Every finding. Filter by status, severity, accepted, scanner, target, tag; search; group by risk or target. Click a risk for description, fix, evidence and history. **Accept** with a reason (stops counting toward the score). **Acceptance rules** tab: auto-accept matching risks (e.g. ports 80/443 on targets tagged `web`). **Export CSV**. |
| **Reports** | Pick targets / tags, severities, whether to include accepted or closed risks, and sections → **Generate report**. The report page prints cleanly (**Print / save as PDF**) and downloads as JSON or CSV. Reports keep the data from the moment they were made. |
| **Integrations** | **Preview only.** Shows the setup screens for email, Slack, Teams, PagerDuty, webhooks, Jira, AWS and Azure. Nothing is saved or sent yet. |
| **Audit log** | Permanent record of authorizations, scans, risk acceptances, rules and reports. |
| **Help** | How the score, statuses and authorization work. |

### Scanners

| Scanner | Mode | Notes |
|---|---|---|
| Web surface | active | probe, technology fingerprint, security headers, TLS expiry, exposed paths, WAF / block detection |
| Port scan | active | TCP connect to ~90 common ports; exposed databases / admin services rated HIGH |
| Nuclei vulnerability | active | Docker; scoped templates (medium+, exposures, misconfig, default logins) |
| Subdomain discovery | passive | certificate transparency (crt.sh) + DNS; results go to Targets → Discovered |
| TLS, Email security, Domain takeover, JS secrets, ZAP | — | being built (see status) |

---

## 3. Authorization

Every active scanner checks the target **on the server** before sending a packet.
The browser can't switch this off.

| Tier | How a target gets it | Allows |
|---|---|---|
| Passive | any target | DNS / certificate-transparency checks only |
| **Attested** | Target drawer → tick "I own … or have written permission" → **Confirm authorization** | active scans |
| **Verified** | Target drawer → **Verify ownership with DNS** → add the `aegis-verify=…` TXT record → **Check DNS now** | active scans |
| Local | automatic for `localhost`, `*.local`, 127/8, 10/8, 172.16/12, 192.168/16 | active scans |

Authorizing a domain covers its subdomains. Unauthorized targets are skipped with a
reason (and the Quick scan API returns 403). Every change is in the audit log.

---

## 4. Configuration

Put settings in `.env.local` (gitignored).

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_DB_PATH` | `data/aegis.db` | SQLite database file |
| `PROXY_URL` / `PROXY_LIST` | unset (off) | Amaan's optional proxy for active stages (see `CLAUDE.md`) |
| `OPENROUTER_API_KEY` | unset | reserved for the AI summary (not built yet) |

Local data: `data/` (database), `scans/` (Quick scan JSON reports). Both are gitignored.

---

## 5. Commands

```bash
npm run dev -- -p 3001   # development server
npm test                 # unit + integration tests (vitest, ~160 tests)
npm run lint             # ESLint
npx tsc --noEmit         # type check
npm run build            # production build (stop the dev server first: they share .next)
npm run seed:demo        # sample data into data/demo.db
```

---

## 6. Project status

| | Area |
|---|---|
| ✅ | Database, health score, risk lifecycle (new / still open / closed / reopened), acceptance rules |
| ✅ | App shell + Jay's design system, Dashboard, Quick scan, Targets, Scans, Risks, Reports, Audit log |
| ✅ | Scan engine: queue (2 at a time), stop, restart recovery, raw results, scheduler (runs scheduled scans every 30 s) |
| ✅ | Ownership verification (attest / DNS TXT / local) enforced server-side |
| 🚧 | New scanners: TLS, email security, domain takeover, JS secrets & source maps, OWASP ZAP |
| 🚧 | Scans: screen to create schedules (the scheduler itself works) |
| 🔲 | AI summary via OpenRouter (needs a key) |
| 🔲 | Real integrations (webhooks, Slack, email); Settings, API keys, REST API |
| 🔲 | Trend charts, workspace switcher, scheduled reports |

The full checklist and progress log: [`docs/LOOP-PLAN.md`](docs/LOOP-PLAN.md).

---

## 7. How the code is organised

```
app/
  (app)/            pages inside the sidebar shell: dashboard, quick-scan, targets,
                    scans, risks, reports, integrations, audit-log, help
  api/scan/*        Quick scan pipeline routes (Amaan), now authorization-guarded
  api/scans, api/risks, api/reports   downloads and exports
components/         ui/ (shared kit), shell/ (sidebar), one folder per screen
lib/
  db/               SQLite client, migrations, one repository per table
  domain/           pure logic: targets, health score, risk lifecycle, rules,
                    schedules, authorization, reports (all unit-tested)
  recon/            the scanning stages (Amaan): discovery, probe, ports,
                    fingerprint, analysis, nuclei, WAF, proxy
  scans/            scanner adapters, gate, executor, queue, scheduler
  services/         server-side composition (dashboard, targets, reports, ...)
tests/              vitest suites mirroring lib/
docs/               plan, handoff notes, HostedScan research
```

Conventions: TypeScript strict, immutable updates, server actions validate every
input, no secrets in code. Architecture notes for contributors are in `CLAUDE.md`.

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| Port 3000 already in use | run Aegis with `-p 3001` and Juice Shop on 3100 |
| "Active scanning is not authorized" | open the target on **Targets** and confirm authorization or verify DNS |
| nuclei finds nothing | Docker running? Run the template update command above |
| `httpx` behaves oddly | a Python `httpx` CLI can shadow ProjectDiscovery's; use `~/go/bin/httpx` |
| Build breaks while dev runs | stop the dev server before `npm run build` |
| Want a clean slate | stop the app and delete `data/aegis.db*` |
