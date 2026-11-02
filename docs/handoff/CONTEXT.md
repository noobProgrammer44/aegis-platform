# Aegis: full working context

Last updated 2026-11-03 (branch `aegis-platform`, commit after `f98068b`).

This file is written for a Claude Code session (Amaan's, or anyone's) picking up
the Aegis platform. It holds everything the previous session knew: setup,
running, architecture, decisions, gotchas, what's done and what's next. If it
disagrees with an older doc, this file wins. `docs/LOOP-PLAN.md` stays the
checklist of record.

---

## 0. Read this first (for Claude)

1. Read this file end to end.
2. Then read `docs/LOOP-PLAN.md` (checklist + progress log),
   `docs/BRANCH-STATUS.md` (what's tested), and
   `docs/hostedscan-reference/GAP-ANALYSIS.md` (what HostedScan has that we don't).
3. Before you edit a file, read it. Most screens share helpers, so check
   `lib/` before writing anything new.
4. Run the gate (section 5) before every commit.
5. Rules from Kartik are in section 13. They are not optional.

---

## 1. People, repo, branches

| Who | Role |
|---|---|
| **Kartik** | Owner of this build. GitHub user **kartikd26** (write access since 2026-11-03). The git author on his Mac is `Nishant-FactWise`, which is his global git config and is expected. |
| **Amaan** (Amaan Khan) | Wrote the original recon pipeline on `main`: discovery, probe, fingerprint, analysis, nuclei, port scan, scan reports, intensity, proxy, WAF detection. Pushes to `origin/main`. |
| **Jay** (UnderPIP97) | UI redesign on `main`: radar surface map, findings-first results, stage rail, palette and glass panels. It is applied across the whole platform. |
| **Amul** | Earlier handoff recipient (portable copy at `~/Downloads/aegis-for-amul`). |

- Repo: `https://github.com/noobProgrammer44/aegis.git`
- **`main`**: the original single-page scanner (Amaan + Jay). Leave it alone; nobody
  pushes platform work to `main`.
- **`aegis-platform`**: the HostedScan-style platform, which is all of this work.
  On Kartik's Mac the local branch is called `feat/hostedscan-parity` and tracks
  `origin/aegis-platform`.
- Push from Kartik's Mac (kd26iosense gets a 403; kartikd26 works):
  ```bash
  git -c credential.helper= -c 'credential.helper=!gh auth git-credential' \
    push origin feat/hostedscan-parity:aegis-platform
  ```
- Getting Amaan's / Jay's new work: `git fetch origin && git merge origin/main`
  into the platform branch. Earlier merges are `3e66b2f`, `d776866` and `41599fa`.
  Conflicts are usually in `app/page.tsx`. On this branch, `app/page.tsx` is just
  a redirect to `/dashboard`, and the old single-page scanner lives at
  `app/(app)/quick-scan/page.tsx`. Port page changes from `main` there.

**Amaan, to see this branch:**
```bash
git fetch origin
git checkout -b aegis-platform origin/aegis-platform   # or: git switch aegis-platform
```

---

## 2. What Aegis is now

`main` is a one-page recon tool. `aegis-platform` turns it into a
**HostedScan-style vulnerability management platform**, with Aegis's own name,
logo and colours:

- **Targets**: domains, URLs, IPs, CIDRs. Each has tags, a label, a health
  score / grade and authorization.
- **Scans**: 10 scanners, queued and run in the background (2 at a time).
  Scans are one-off or scheduled.
- **Risks**: deduplicated per target with a lifecycle (open, still open,
  closed when no longer found, accepted). Evidence includes OWASP / CWE / WASC
  and per-URL instances with request / response.
- **Health score**: 0 (best) to 1000 (worst), graded A–F. Daily snapshots
  feed the trend.
- **Reports**: HTML (print to PDF), JSON, CSV.
- **Dashboard, Audit log and Help**. Integrations is a **mock**, and Settings
  and API docs are placeholders (see section 10).

Everything persists in SQLite (`data/aegis.db`). This is not a UI mock: scans
hit real targets and write real rows.

---

## 3. Machine setup

| Tool | Needed for | Check |
|---|---|---|
| Node 20+ (Kartik: 23.11) | the app | `node -v` |
| Docker (Kartik: 29.x) | nuclei, ZAP, Juice Shop | `docker --version` |
| `projectdiscovery/nuclei:latest` (1.2 GB) | Nuclei scanner | `docker images` |
| `zaproxy/zap-stable` (3.6 GB) | ZAP baseline / full | `docker pull zaproxy/zap-stable` |
| `bkimminich/juice-shop` | safe local target | `docker pull bkimminich/juice-shop` |
| subfinder (optional, v2.17) | second subdomain source when crt.sh is down | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`. The binary is looked up in `~/go/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, then PATH |

- Nuclei templates live in the Docker volume `aegis-nuclei`. They are
  **downloaded automatically before the first nuclei scan**
  (`lib/recon/nuclei-templates.ts`, about a minute). To pre-warm them manually:
  `docker run --rm -v aegis-nuclei:/root projectdiscovery/nuclei:latest -update-templates`
- Kartik's Mac also has dnsx, httpx, katana and nuclei in `~/go/bin`, nmap
  (brew) and sslyze (pipx). **None of them are used by the code yet.** The
  scanners are pure Node or Docker. Watch out: on macOS a Python package
  installs a different `httpx` CLI.
- Ports: **Juice Shop on 3100**, **Aegis on 3001**. Port 3000 is taken on
  Kartik's Mac. Postgres on 5544 is another project; ignore it.

---

## 4. Run everything

```bash
npm install

# safe, intentionally vulnerable target
docker run -d -p 3100:3000 --name aegis-juiceshop bkimminich/juice-shop
#   (later: docker start aegis-juiceshop)

npm run dev -- -p 3001          # http://localhost:3001 lands on /dashboard
```

- **Demo data** (never touches the real DB):
  `npm run seed:demo`, then `AEGIS_DB_PATH=data/demo.db npm run dev -- -p 3001`.
- The **real DB** is `data/aegis.db`. It is gitignored, along with all of
  `data/`. To start fresh, stop the server and delete `data/aegis.db*`;
  migrations recreate it.
- ZAP writes its work files to `data/zap-runs/`, inside the project, because
  Docker Desktop on macOS doesn't share the OS temp dir.
- The runner (queue) and scheduler start from `instrumentation.ts` when the
  server boots. **After editing scanner code, restart the dev server.** The
  runner keeps old module instances, so hot reload doesn't reach queued scans.

### First real scan, end to end
1. Go to **Targets → Add targets** and enter `localhost:3100`. Local targets are
   authorized automatically.
2. Go to **Scans → New scan**, a 4-step wizard: pick scanners, then targets,
   then configure (once or a schedule; Polite / Normal / Aggressive; email
   policy), then review and **Start**.
3. Watch progress on **Scans**. Open a scan for live progress, risks and the raw
   JSON download.
4. **Risks**: expand a row for threat bars, OWASP / CWE, instances and
   request / response. Accept from the row.
5. **Reports**: generate HTML / JSON / CSV.
6. **Dashboard**: the period selector plus the **target filter** (`?target=`).

For a real domain: add it, then open it on **Targets → Authorization** and
either tick "I own…" (attest) or verify with a DNS TXT record. Without one of
those, active scanners skip it with a reason.

---

## 5. Gate (run before every commit)

```bash
npx tsc --noEmit        # ignore errors under .next/types (stale route types; build regenerates them)
npm run lint
npm test                # vitest, 202 tests in 28 files as of 2026-11-03
npm run build           # STOP the dev server first: both use .next/
```

UI changes also get loaded in the browser on the dev server.

---

## 6. Architecture map

```
app/
  page.tsx                    redirect -> /dashboard
  (app)/layout.tsx            shell (sidebar); Jay's survey-grid background sits under it (shell root is relative z-10)
  (app)/dashboard             loadDashboard(db, ws, period, now, targetId?)  lib/services/dashboard.ts
  (app)/quick-scan            Amaan + Jay's original single-page scanner (calls /api/scan/*)
  (app)/targets               table, drawer (authorization panel, risks, recent scans, metadata), Discovered tab
  (app)/scans                 tabs Scans / Scheduled Scans; actions.ts = server actions
  (app)/scans/new             New Scan wizard (components/scans/wizard/*)
  (app)/scans/[id]            scan detail, live progress, partial note, raw results download
  (app)/risks                 inline-expand risk list, filters (?target= works), acceptance rules
  (app)/reports, reports/[id] builder + printable report page
  (app)/integrations          MOCK preview (clearly labelled)
  (app)/settings              placeholder ("Nothing to configure yet")
  (app)/audit-log, help      real
  (app)/api-docs              placeholder until the REST API exists (item 15)
  api/scan/{discovery,probe,ports,fingerprint,analysis,nuclei,report}   Quick scan routes (Amaan's), guarded by lib/scans/route-guard.ts (403 if host not authorized)
  api/scans/[id]/results/[fileId]   raw scan output download
  api/reports/[id]/download, api/risks/export   CSV / JSON downloads

lib/
  db/client.ts, migrations.ts, repos/*   better-sqlite3, one repo per table, all workspace-scoped
  domain/*        pure logic with tests: health-score, risk-lifecycle (mergeScanRisks), acceptance,
                  authorization (tiers), schedule, targets (parse + filterCoversTarget), insights,
                  owasp, evidence, report, risk-table, target-table, network
  services/*      orchestration over repos: dashboard, scan-requests, authorization, acceptance, reports, targets
  scans/
    catalog.ts    scanner metadata (label, mode, tags) shown in the wizard
    scanners/     adapters: recon.ts (surface, ports, nuclei, discovery over lib/recon), extra.ts (TLS, email,
                  takeover, JS secrets, ZAP), types.ts (Scanner, ScannerOutput incl. skipped / partial)
    checks/       tls.ts, email.ts, takeover.ts, js-secrets.ts, zap.ts  (pure parsers + runners)
    execute.ts    runs one scan: gate per target -> scanner -> mergeScanRisks -> health -> audit
    runner.ts     DB-backed queue, CONCURRENCY = 2, crash recovery
    scheduler.ts  every 30 s queues due schedules
    gate.ts, route-guard.ts   authorization enforcement (platform + quick-scan routes)
    tools.ts      runCommand (no shell, timeouts), dockerAvailable, image checks
    availability.ts  greys out scanners when Docker / image missing
  recon/          Amaan's pipeline: discovery (crt.sh + subfinder), probe, fingerprint, analysis, ports,
                  nuclei (+ nuclei-templates), intensity, proxy, waf, score
                  + new: exposed-paths.ts (false-positive rules), cdn-edge.ts (Cloudflare edge ports), subfinder.ts
  validation/     zod schemas (scan-request.ts, limits.ts). Keep zod out of client components (bundle size).
  actions/result.ts   ActionResult / INITIAL_RESULT (a "use server" file can't export consts)
  ui/             format helpers (labels, timeAgo, isPartialScan), cx
components/       brand, shell, ui (Button, Card, Table, segmented controls, badges), dashboard, targets,
                  scans (+ wizard), risks, reports, integrations
types/aegis.ts    all domain types; types/recon.ts = Amaan's pipeline types (Finding, LiveHost, ...)
tests/            vitest, mirrors lib/ (db, domain, scans, services, recon, ui); tests/db/helpers.ts gives useMemoryDb()
scripts/seed-demo.ts
instrumentation.ts  starts runner + scheduler (Node runtime only)
```

**Data flow:** UI → server action (`app/(app)/*/actions.ts`, validates with zod) →
`lib/services/*` → `lib/db/repos/*`. Scans go through the queue:
`createScan(QUEUED)` → runner picks up → `executeScan` → for each target:
authorization gate, then `scanner.run()` → `mergeScanRisks` (new / still open /
closed) → `saveRisks` → `recomputeHealth` (+ daily snapshot) → audit entry →
scan `SUCCEEDED / FAILED / BLOCKED / STOPPED`.

---

## 7. Database

- SQLite via better-sqlite3. File: `AEGIS_DB_PATH`, default `data/aegis.db`.
- Migrations live in `lib/db/migrations.ts`, applied in order and tracked with
  `PRAGMA user_version`:
  1. the base schema;
  2. `scans.intensity`;
  3. `scheduled_scans.intensity`.

  **Add a new migration; never edit an old one.**
- Tables: workspaces, targets, discovered_domains, authorizations, audit_log,
  scans, scan_results, risks, acceptance_rules, scheduled_scans, reports,
  scheduled_reports, webhooks, webhook_deliveries, api_keys, settings,
  notifications, health_snapshots.
- Every repo function takes `workspaceId`. There is a single workspace
  `ws_default` (`lib/workspace.ts`) until item 17.
- Repo updates are immutable: merge a patch into a new object, pin `id` and
  `workspaceId`, and drop undefined fields.
- Risk identity is `riskFingerprint(scanType, finding)`: a sha256 of the
  scanner, the title with digits masked, the host and the port. **If you change
  a finding's title, the old risk closes and a new one opens.**

---

## 8. Authorization (what the code actually does)

`CLAUDE.md` describes a 3-tier idea. The implementation (`lib/domain/authorization.ts`) uses:

| Tier | How you get it | Allows |
|---|---|---|
| 0 | nothing | passive scanners only (Discovery, Email, Takeover) |
| 1 | **attest** ("I own this / have written permission", optional note) | all active scanners (`ACTIVE_SCAN_MIN_TIER = 1`) |
| 2 | **DNS TXT** verified, or **local / private** target (automatic) | same as 1, stronger proof |

- The gate runs server-side per target, in `lib/scans/gate.ts`, inside `executeScan`.
- `lib/scans/route-guard.ts` makes the Quick scan routes `/api/scan/*` return
  **403** for hosts that aren't authorized. The `activeAllowed` flag from the
  browser can no longer authorize anything on its own.
- Every attest, verify and revoke is written to the audit log.

---

## 9. Scanners

| ID | Label | Mode | Needs | Code | Notes |
|---|---|---|---|---|---|
| SURFACE | Web surface | active | Node | recon.ts → probe / fingerprint / analysis | headers, TLS expiry, exposed paths, tech. Exposed-path rules in `lib/recon/exposed-paths.ts` (2xx only; .git/config and .env must match real content; soft-404 baseline from a random path) |
| NMAP | Port scan | active | Node | `lib/recon/ports.ts` | TCP connect, ~90 ports. Cloudflare-proxied hosts get "Open port N — Cloudflare edge" (`cdn-edge.ts`). Open ports become LOW risks |
| TLS | TLS / SSL | active | Node | checks/tls.ts | expiry, trust, hostname, legacy TLS 1.0/1.1, weak key by type (RSA < 2048, EC < 224) |
| JS_SECRETS | JS secrets & source maps | active | Node | checks/js-secrets.ts | 10 key formats, stored **masked**; source maps. Uses a lenient undici agent (bad certs OK) |
| NUCLEI | Nuclei vulnerability | active | Docker | `lib/recon/nuclei.ts` | scoped templates (medium+, exposure / misconfig / panels / default-login). WAF throttling gives `partial` (see below) |
| DISCOVERY | Subdomain discovery | passive | Node (+ subfinder) | `lib/recon/discovery.ts` | crt.sh + subfinder in parallel, merged; fails only if both fail; resolves ≤ 75 names; results go to Targets → Discovered |
| EMAIL | Email security | passive | DNS | checks/email.ts | SPF, DMARC |
| TAKEOVER | Domain takeover | passive | DNS | checks/takeover.ts | dangling CNAMEs to ~25 services, target + discovered subdomains |
| ZAP_PASSIVE | OWASP ZAP baseline | active | Docker | checks/zap.ts | Automation Framework YAML, `traditional-json-plus` report → OWASP tags, CWE / WASC, instances with request / response |
| ZAP_ACTIVE | OWASP ZAP full scan | active | Docker | checks/zap.ts | attack payloads; only with explicit OK on targets you own |

- **Partial results:** a scanner can return `partial: "<reason>"`. Its risks are
  recorded, but risks it couldn't check stay open (not closed). The scan shows
  **Partial** in the Scans list, on the scan page and on the dashboard. Today
  only nuclei uses this, when a WAF / CDN throttles it.
- **Intensity** (`lib/recon/intensity.ts`): polite (4 conc, 250 ms delay),
  normal, aggressive. It is chosen per scan / schedule in the wizard.
- **Docker localhost:** containers can't reach the host's `localhost`.
  - ZAP uses `forDocker()` in `lib/scans/tools.ts`, plus
    `--add-host host.docker.internal:host-gateway`.
  - nuclei has its own rewrite in `lib/recon/nuclei.ts`, which maps hosts back
    for reporting.

---

## 10. Screens: what's real

| Screen | Status |
|---|---|
| Dashboard | real: health gauge, risk tiles, recent scans / risks / discovered, insights, period + **target filter** |
| Quick scan | real (the original `main` flow), guarded by authorization |
| Targets | real: add / paste many, tags, grades, drawer with authorization (attest / DNS / revoke), Discovered domains tab |
| Scans | real: list, stop, delete, detail, raw download; **New Scan wizard**; **Scheduled Scans** tab (run now / pause / delete) |
| Risks | real: HostedScan-style inline rows, threat bars, OWASP / CWE / WASC links, Formatted / Table / JSON, Instances / References / History tabs, accept / unaccept, acceptance rules, CSV / JSON export, 30 rows per page |
| Reports | real: builder, printable branded report, JSON / CSV |
| Audit log, Help | real pages |
| API docs | placeholder ("The REST API isn't enabled yet"; comes with item 15) |
| Integrations | **MOCK preview only**, labelled as such. Nothing is saved or sent |
| Settings | placeholder |
| Email notifications | addresses + policy are **saved** on schedules; **nothing is sent yet** (item 14) |

---

## 11. Environment variables

| Var | Default | Use |
|---|---|---|
| `AEGIS_DB_PATH` | `data/aegis.db` | SQLite file (`data/demo.db` for demo) |
| `PROXY_URL` / `PROXY_LIST` | unset | Amaan's opt-in proxy for active stages (http / socks) |
| `OPENROUTER_API_KEY` | unset | planned AI summary (item 13); not wired into the platform yet |

Put them in `.env.local` (gitignored). Never commit secrets.

---

## 12. Live test record (2026-11-03)

Kartik confirmed **faclon.com** and **factwise.io** are his. Both are added
(tags `owned, prod`) and attested in his DB. All 9 scanners ran at polite, with
ZAP in passive mode only:

- faclon.com is behind **Cloudflare**; factwise.io is on **Netlify** and returns
  a 200 soft-404 page for every path.
- Discovery found **60** names for faclon.com (33 resolve) and **17** for
  factwise.io.
- Nuclei: templates OK, but both hosts throttle it, so the result is **Partial**.
- **False positives found and fixed:**
  - a Cloudflare 403 was counted as an exposed `.git/config` / `.env`;
  - soft-404 pages were counted as `/admin`, `/swagger`, `/api-docs`;
  - Cloudflare edge ports 2082 / 2083 were labelled cPanel;
  - a P-256 EC key was called a "weak 256-bit RSA key".

  A re-run closed them all.
- Real findings left: missing CSP / X-Frame-Options / Referrer-Policy /
  X-Content-Type-Options, DMARC `p=none`, missing SRI, `SameSite=None` cookie,
  `X-Powered-By` leak (factwise.io).

Juice Shop (`localhost:3100`) is the target for intrusive tests (ZAP full,
nuclei CVE templates). The nuclei `cve` tag can crash Juice Shop.

---

## 13. Kartik's rules (follow exactly)

- **Build it yourself; no subagents.** Do a careful self-review before ticking
  an item.
- **No claude.ai Artifacts.** Write local files and give the path.
- **Commit locally per finished item**, using conventional commits
  (`feat:`, `fix:`, `docs:`, ...) with no attribution lines.
- **Never push or take outward-facing actions without asking.** When pushing,
  push only to `aegis-platform`, never `main`.
- Kartik wants **real, working BE + FE**, not UI only. Verify on the real DB, not
  just `seed:demo`.
- **Active scans only against local targets or attested / DNS-verified targets
  the user owns.** Default to polite. No ZAP full or nuclei CVE templates on
  real domains unless Kartik asks.
- Keep **Aegis branding**. HostedScan is the model for features and information
  architecture only; no copying of their branding or copy.
- HostedScan research is **read-only** (Kartik's account): never start scans
  there. Don't handle anyone's passwords.
- **Code style:**
  - immutable updates (no in-place mutation);
  - files under ~400 lines (800 max), small functions;
  - no `console.log`;
  - validate input at boundaries (zod);
  - no shell strings for commands (`runCommand(bin, args[])`);
  - tests first for new logic (vitest);
  - match the surrounding code's style and comment density.
- Kartik writes short, typo-heavy messages. Infer the intent and keep going
  ("pls dont stop"). Give short progress notes.

---

## 14. Gotchas we hit (save yourself the time)

- **zod in a client component** pushed `/targets` to 104 kB. Shared limits now
  live in `lib/validation/limits.ts`.
- **A `"use server"` file can only export async functions.** Put constants and
  types in `lib/actions/result.ts`.
- **Tailwind v4 needs literal class names.** Never build a class by slicing
  strings (see `SEVERITY_ACCENT.row`).
- **Jay's fixed background overlay** covered the shell. The fix is
  `relative z-10` on the shell root.
- **`.next/types` route-type errors** in `tsc` are stale. Ignore them; the build
  regenerates them.
- **Build and dev share `.next`.** Stop the dev server before `npm run build`,
  then restart it.
- **Scanner code changes need a dev-server restart** (runner instance on
  `globalThis`).
- **ZAP "permission denied"** means the work dir isn't shared with Docker. Keep
  it in `data/zap-runs`.
- **Nuclei "finishes" with 0 requests** when the template volume is empty. This
  is now auto-fixed by `ensureNucleiTemplates`.
- **crt.sh is often overloaded** (502 / timeouts). Discovery retries it and also
  uses subfinder.
- **Cloudflare / Netlify sites** produce WAF 403s, soft 404s and edge ports.
  Check findings against the real response with `curl` before trusting them.
- **Playwright MCP** saves screenshots only under
  `/Users/kartikd/Downloads/new for amul`. Another session may share the
  browser, so retry if a page navigates away.
- The **harness blocks bare `sleep`**. Wait with until-loops on a condition.

---

## 15. Done / next

**Done** (`docs/LOOP-PLAN.md` items 1–12; 10 finished on 2026-11-03):
- data layer;
- domain logic;
- server-side authorization;
- scanner framework + 10 scanners;
- runner / queue / scheduler;
- app shell (Jay's design);
- Dashboard (+ target filter);
- Targets;
- Scans (+ wizard, Scheduled tab);
- Risks (HostedScan-style evidence);
- Reports;
- the nuclei and discovery fixes, and the false-positive fixes above.

**Next, in order** (from GAP-ANALYSIS "Proposed build order" + LOOP-PLAN):
1. Scan rows with inline expansion: "vs previous scan" counts, Crawled URLs,
   and a Report ▾ menu with raw outputs (PDF / HTML / JSON).
2. **Trends** (item 16): Open Risks over time, Exposure Window (<30 / 30–90 /
   >90 days), and Health Score on the dashboard and per target. Daily snapshots
   are already recorded in `health_snapshots`.
3. **Settings** (item 15): General (time zone), Scanners status, **API keys**
   (hashed) and REST `/api/v1/*`, branding.
4. **Integrations for real** (item 14): signed webhooks + delivery log, Slack,
   email via SMTP (NEVER / ON_CHANGES / ALWAYS) with an outbox when SMTP is
   unset. Then Scheduled Reports.
5. **AI summary via OpenRouter** (item 13), using `OPENROUTER_API_KEY`, with a
   clean fallback when no key is set.
6. **Workspaces** (item 17).
7. **Final pass** (item 18): end-to-end on Juice Shop, a security review, docs.

The P2 / P3 items in GAP-ANALYSIS (Nmap UDP / full range, OpenVAS, cloud
target imports, SSO) come after that.

**Known leftovers in Kartik's DB:**
- a test schedule named "Email security" (weekly, all targets, enabled), which
  Kartik can delete on Scans → Scheduled;
- factwise.io's attestation has no note.

---

## 16. If you change Amaan's recon code

The platform calls these directly. If you change their signatures, update
`lib/scans/scanners/recon.ts` (and `extra.ts`) as well.

| Function | File |
|---|---|
| `discover(domain)` | `lib/recon/discovery.ts` |
| `probe(subdomains, active, intensity)` | `lib/recon/probe.ts` |
| `fingerprint(hosts, active, intensity)` | `lib/recon/fingerprint.ts` |
| `analyze(liveHosts, fingerprints, active)` | `lib/recon/analysis.ts` |
| `scanPorts(hosts, active, intensity)` | `lib/recon/ports.ts` |
| `runNucleiStream(live, callbacks, { signal, intensity })` | `lib/recon/nuclei.ts` |

Findings use `types/recon.ts` `Finding` and are converted to risks by
`lib/scans/findings.ts`. INFO findings are dropped, except open ports, which
become LOW. Quick scan (`/quick-scan`) benefits from the same fixes.

---

## 17. Resume prompt

```
Continue the Aegis platform on branch aegis-platform. Read docs/handoff/CONTEXT.md,
then docs/LOOP-PLAN.md and docs/hostedscan-reference/GAP-ANALYSIS.md. Build the next
item from CONTEXT.md section 15 fully (BE + FE, tests first, real DB), run the gate
(tsc, lint, test, build with the dev server stopped), check the page in the browser
on port 3001, tick LOOP-PLAN with a progress-log line, commit. Don't push without
asking. Active scans only on local or attested targets.
```
