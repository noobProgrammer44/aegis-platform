# Branch `aegis-platform`: what's done (reference for Claude Code)

Status as of 2026-11-03. This branch turns the single-page scanner on `main` into
a HostedScan-style platform: targets, scans, risks, reports. It contains all of
`main` up to `fce5f79` (Amaan's port scan, reports, intensity, proxy, WAF
detection, and Jay's redesign). `main` itself is unchanged.

Read with: `README.md` (setup and usage), `docs/LOOP-PLAN.md` (18-item checklist
and progress log).

## Run it

```bash
git fetch origin && git checkout aegis-platform && npm install
docker run -d -p 3100:3000 --name aegis-juiceshop bkimminich/juice-shop
npm run dev -- -p 3001          # app on :3001, Juice Shop on :3100
npm test                        # 161 tests
```

## Where main's code went

| On `main` | On this branch |
|---|---|
| `app/page.tsx` (Jay's scanner UI) | `app/(app)/quick-scan/page.tsx`, inside the sidebar shell. Its own header is replaced by a status bar; otherwise unchanged. `/` redirects to `/dashboard`. |
| `lib/recon/*` (Amaan's stages) | unchanged, and reused by the platform scan engine through `lib/scans/scanners/recon.ts` |
| `app/api/scan/*` | unchanged, plus a server-side authorization guard (see below) |
| `app/globals.css` (Jay's palette) | kept as the global theme; grade and print colours added |

## Done and how it was tested

| Area | Where | Tested by |
|---|---|---|
| SQLite data layer, one repo per table, workspace-scoped | `lib/db/` | 53 repo tests on `openDb(":memory:")` |
| Health score (0–1000, A–F), risk lifecycle, acceptance rules, schedules, target parsing | `lib/domain/` | unit tests |
| Scan engine: scanner adapters, executor, queue (2 at a time), stop, restart recovery, scheduler | `lib/scans/`, `instrumentation.ts` | executor tests with fake scanners; real Web surface + Port scan of Juice Shop from the UI produced risks and a health score |
| Ownership verification: attest / DNS TXT / local, enforced server-side | `lib/domain/authorization.ts`, `lib/services/authorization.ts`, `lib/scans/gate.ts`, `lib/scans/route-guard.ts` | unit + service tests (fake DNS); live: `/api/scan/probe` returns 403 for an unauthorized host even with `activeAllowed: true`, 200 for localhost; real TXT lookup; attest flow in the browser |
| Dashboard, Targets, Scans, Risks, Reports, Audit log, Help | `app/(app)/*`, `components/*` | each screen checked in the browser on real data; actions (add / accept / rules / generate report / CSV + JSON downloads) exercised |
| Quick scan after merging Jay + Amaan | `app/(app)/quick-scan` | full scan of `localhost:3100` in the browser, report download via API |
| 5 new scanners: TLS, JS secrets & source maps, OWASP ZAP baseline / full, email security (SPF / DMARC), domain takeover | `lib/scans/checks/*`, `lib/scans/scanners/extra.ts` | 17 unit tests on the pure parts; live through the Scans page: TLS found a self-signed + expiring cert on a local HTTPS server, JS secrets found a planted fake key (stored masked only) and a source map, ZAP baseline produced 9 findings on Juice Shop, email / takeover ran on example.com; unauthorized targets skipped with reasons |
| New Scan wizard + Scheduled Scans tab, dashboard target filter | `app/(app)/scans/new`, `components/scans/wizard/`, `lib/services/scan-requests.ts`, `lib/services/dashboard.ts` | service tests; wizard driven end to end in the browser |
| Live run on real domains (faclon.com, factwise.io, owned, attested, polite) | all 9 scanners | nuclei templates auto-download, subfinder + crt.sh discovery (60 / 17 names), false positives fixed (Cloudflare 403 / soft 404 exposed paths, Cloudflare edge ports, EC keys), WAF-throttled nuclei reported as Partial |
| Integrations | `app/(app)/integrations` | **preview mock only**, nothing saved or sent |

Gate before every commit: `npx tsc --noEmit`, `npm run lint`, `npm test`,
`npm run build`. All green at the time of writing.

## Not tested yet

- a scheduled scan firing live (the scheduler is unit-tested only)
- DNS verification succeeding against a real domain (only tested with a fake resolver)
- Windows

## Behaviour changes that affect `main`'s code

- **`/api/scan/probe|ports|fingerprint|analysis|nuclei` now reject unauthorized
  hosts with 403.** Localhost and private ranges still pass automatically. Any other
  host must be added on Targets and attested or DNS-verified first. The
  `activeAllowed` flag is still read, but it can no longer authorize anything on
  its own.
- Surface scan exposed-path rules moved to `lib/recon/exposed-paths.ts` (2xx only,
  content signatures for .git/config and .env, soft-404 baseline). The port scan
  labels Cloudflare-proxied ports as "Cloudflare edge" (`lib/recon/cdn-edge.ts`).
  Quick scan gets both fixes too.
- The platform scanners call `probe`, `fingerprint`, `analyze`, `scanPorts` and
  `runNucleiStream` directly. If you change their signatures, also update
  `lib/scans/scanners/recon.ts`.
- Amaan's proxy is picked up automatically when `PROXY_URL` / `PROXY_LIST` are set.
  Open question for the team: proxy *rotation* looks like block evasion, so
  consider keeping only a single fixed proxy.

## Open work

ZAP full scan not run live yet (baseline was); a screen to create schedules; AI summary via OpenRouter (needs `OPENROUTER_API_KEY`; Amaan's Markdown
report already has an `aiSummary` slot); real integrations; settings / API keys /
REST API; trend charts; workspace switcher.

## Conventions on this branch

TypeScript strict; immutable updates; files under ~400 lines; server actions
validate every input and write audit entries; pure logic in `lib/domain/` with
tests; no `console.log`. Merging `main` in: the usual conflict is `app/page.tsx`.
Keep it as the redirect and apply `main`'s change to
`app/(app)/quick-scan/page.tsx`.
