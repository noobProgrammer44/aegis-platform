# Aegis: HostedScan-parity build plan (loop checklist)

Branch `feat/hostedscan-parity`. One item per commit. Tick an item only after
`npx tsc --noEmit`, `npm run lint`, `npm test` and `npm run build` pass and, for UI
items, the page renders on the dev server (`npm run dev -- -p 3001`).

Feature research: `docs/hostedscan-reference/README.md`.

## Decisions

- **Same layout and features as HostedScan, Aegis identity.** Sidebar, dashboard,
  targets, scans, risks, reports, integrations and settings follow HostedScan's
  structure. Name, logo, colours and copy stay Aegis (dark slate + cyan tokens in
  `app/globals.css`).
- **Persistence:** SQLite via `better-sqlite3` at `data/aegis.db` (gitignored).
  Thin repository modules in `lib/db/`. JSON columns for nested data.
- **Jobs:** scans run in-process in a queue (`lib/scans/runner.ts`, concurrency 2).
  The scheduler (scheduled scans and reports) starts from `instrumentation.ts`.
- **Authorization is server-side.** Every active scanner checks the target's
  authorization record before it runs. The client never sends `activeAllowed`.
  Tiers: 0 passive (any target), 1 attested (checkbox + audit entry),
  2 DNS-verified (`aegis-verify=<token>` TXT). Localhost/private ranges are
  auto-authorized. Intrusive scanners (nuclei, ZAP active) need tier 1+.
- **Scanners** resolve a local binary first (Go bin dir, PATH), then a Docker
  image, else report "unavailable" and the scan degrades instead of failing.
  ProjectDiscovery tools come from GitHub via `go install`.
- **Not built:** OpenVAS (multi-GB feed sync), Nessus (commercial), SAML SSO,
  AWS/Azure import (needs cloud credentials), user accounts (local tool; the REST
  API is protected by API keys).
- **Tests:** vitest for pure logic (health score, risk lifecycle, rule matcher,
  target parsing, schedules, parsers, authorization).

## Checklist

### Foundation
- [x] 1. Tooling: vitest + test script, `better-sqlite3`, `zod`; `lib/db` schema +
      migrations + repositories (targets, scans, risks, schedules, reports, rules,
      authorizations, audit log, webhooks, api keys, settings, notifications).
- [x] 2. Domain logic with tests: target parsing (IPv4 / domain / URL / CIDR),
      health score (0-1000, A-F, tier floors + diminishing returns), risk lifecycle
      (new_open / still_open / closed / reopened), acceptance rule matcher,
      schedule next-run.
- [x] 3. Server-side authorization service (tiers, attest, DNS TXT verify, local
      auto-auth, audit log) and enforce it in the existing `/api/scan/*` routes.

### Scan engine
- [ ] 4. Scanner framework + tool resolver (local binary / Docker / unavailable)
      and adapters for the existing pipeline: Web surface (probe + fingerprint +
      headers + TLS expiry + exposed paths), Nuclei, Subdomain discovery (crt.sh +
      subfinder) feeding "Discovered domains".
- [x] 5. More scanners: Nmap TCP port scan, TLS/SSL (sslyze, Node fallback),
      Email security (SPF / DMARC / MX), Domain takeover (dangling CNAME), JS
      secrets + source maps ("vibe-code leaks"), OWASP ZAP baseline + full (Docker).
- [x] 6. Scan runner + queue (QUEUED -> RUNNING -> SUCCEEDED / FAILED / STOPPED,
      progress, stop), risk merge + health recompute, events; scheduler for
      scheduled scans via `instrumentation.ts`.

### UI
- [x] 7. App shell: sidebar (Dashboard, Targets, Scans, Risks, Reports,
      Integrations, Settings, Audit log; Quick scan, API docs, Help), collapse,
      shared UI kit (buttons, tiles, chips, drawer, modal, table, gauge); move the
      old single page to `/quick-scan`.
- [x] 8. Dashboard: period selector, scans-in-progress / scheduled pill, New Scan,
      health gauge + about-your-score, severity tiles + accepted / closed, recent
      scans / risks / discovered domains, insight cards.
- [x] 9. Targets: table (grouping, search, sort, filters, tags, grade, discovered,
      source, last scanned), Add target (target / tags / label, bulk paste),
      discovered domains -> add, target drawer (stats, tabs, gauge, rescan,
      report), authorization panel (attest / DNS verify).
- [ ] 10. Scans: list (state, progress, type, targets, new / open / closed, stop,
      delete), New Scan modal (scanner cards, passive vs full, target / tag
      selection, run now or schedule, email chips), scan detail with live
      progress + raw results download, Scheduled tab.
- [x] 11. Risks: table (filters by level / status / accepted / scanner / target /
      tag, search, group by title or target), risk drawer (description, solution,
      references, CVSS, evidence, history), accept / unaccept with reason,
      acceptance rules editor, CSV export.
- [x] 12. Reports: builder (name, format HTML-PDF / JSON / CSV, targets filter, risk
      filter, sections), printable branded report page (cover, executive summary,
      coverage, target breakdown, details), report history, scheduled reports.
- [ ] 13. AI summary via OpenRouter (Phase 8): scan + report executive summary,
      top risks, next actions; model setting; clean fallback with no key.
- [ ] 14. Integrations: outgoing webhooks (HMAC-signed, events, test button,
      delivery log), Slack incoming webhook, email via SMTP with
      NEVER / ON_CHANGES / ALWAYS policy and an outbox view when SMTP is unset.
- [ ] 15. Settings: API keys (hashed, create / revoke), branding (white-label
      report), health threshold, scanner status page, data reset; REST API
      `/api/v1/*` with key auth + API docs page.
- [ ] 16. Trends: dashboard open-risks-over-time + exposure window charts, target
      drawer Trends tab (daily snapshots table).
- [ ] 17. Workspaces: workspace switcher, data / keys / webhooks isolated per
      workspace.

### Finish
- [ ] 18. End-to-end run against local Juice Shop (all available scanners), fix
      what breaks, README + CLAUDE.md update, security pass (command args never
      via shell, input validation, key hashing, SSRF notes), final review.

## Progress log
- 2026-11-02: plan, reference research and handoff docs written. Item 1 started:
  `types/aegis.ts`, `lib/db/migrations.ts`, `lib/db/client.ts`, deps added
  (better-sqlite3, zod, vitest). Remaining for item 1: `lib/db/repos/*`, `test`
  script + repo tests, `better-sqlite3` in `serverExternalPackages`. Scanners
  installed on Kartik's Mac (see `docs/handoff/session-context.md`).
- 2026-11-02: item 1 done (continued in a new session after the handoff).
  `lib/db/repos/*`: one module per table, every read and write workspace-scoped,
  updates return new objects; `lib/db/errors.ts` (`DuplicateError`), `lib/db/sql.ts`.
  `npm test` (vitest, `vitest.config.ts` with the `@/` alias): 53 repository tests on
  `openDb(":memory:")`. `better-sqlite3` added to `serverExternalPackages`.
- 2026-11-02: item 2 done. Pure modules in `lib/domain/`: `targets.ts` (domain / URL /
  IPv4 / host:port / CIDR up to /24, bulk paste), `network.ts` (IPv4, CIDR, local
  ranges for auto-auth), `health-score.ts` (tier floors, 80% / 20% diminishing lifts),
  `acceptance.ts` (AND of conditions, empty rule matches nothing, manual acceptances
  never overridden), `risk-lifecycle.ts` (new / still open / reopened / closed, only
  closes same-scanner risks on scanned targets), `schedule.ts` (anchored next run, UTC,
  month-end clamping). 45 new tests, 98 total.
- 2026-11-02: item 3 deferred (the session's replies on it kept getting cut off;
  resume it together with Kartik). Items 4-6 still open.
- 2026-11-02: item 7 done. `app/(app)/` route group with `components/shell/sidebar.tsx`
  (collapse remembered in localStorage, active link, workspace label), UI kit in
  `components/ui/` (button, card / page header / empty state, chips + severity and
  grade badges, severity tiles + stat bars, table, drawer + modal, health gauge), grade
  colour tokens. Old page moved to `/quick-scan`, `/` redirects to `/dashboard`.
  Dashboard already shows real health + severity counts from the database; other
  sections show empty states. `lucide-react` added. Checked in the browser at 1440px.
- 2026-11-02: item 8 done. `lib/services/dashboard.ts` loads everything server-side;
  `lib/domain/insights.ts` (periods, issue grouping, top issues, most critical /
  frequent / vulnerable, 30-day trend from snapshots) with tests; panels in
  `components/dashboard/`. Period selector is plain links (`?period=30d|90d|1y|all`).
  `npm run seed:demo` (tsx) fills `data/demo.db` with sample data; browse it with
  `AEGIS_DB_PATH=data/demo.db npm run dev -- -p 3001`. Checked in the browser.
- 2026-11-02: merged Amaan's origin/main 474096c (port scan, Markdown reports, scan
  intensity, scoped nuclei); his page changes now live in `/quick-scan`.
- 2026-11-02: item 9 done except the authorization panel (waits for item 3). Server
  actions in `app/(app)/targets/actions.ts` (add / bulk paste, edit label + tags,
  delete, promote discovered domain; all validated server-side and audit-logged).
  `components/targets/`: table with search, sort, grade / tag filters and tag
  grouping; add modal; drawer with gauge, stat strip, Risks / Recent scans /
  Metadata tabs; Discovered tab. Pure table logic in `lib/domain/target-table.ts`.
  Checked in the browser on demo data. Next: items 4-6 so scans write real risks.
- 2026-11-02: scans now write real risks (item 6 done; items 4 and 10 partly).
  `lib/scans/`: `scanners.ts` adapters over Amaan's lib/recon stages (Web surface =
  probe + fingerprint + analysis, Port scan = his TCP connect scan, Nuclei, Subdomain
  discovery via crt.sh); `catalog.ts` browser-safe metadata; `findings.ts` finding ->
  risk mapping with stable fingerprints (digits masked); `gate.ts` server-side check:
  active scanners only touch local / private-network targets until item 3 adds
  attestation + DNS verification; `execute.ts` runs a scan (gate, run, raw results
  file, merge risks, recompute health + snapshots, audit); `runner.ts` DB-backed queue
  (concurrency 2, stop, restart recovery); `scheduler.ts` + `instrumentation.ts` queue
  due scheduled scans every 30s. Migration 2 adds `scans.intensity`.
  Scans page: list with live progress (auto refresh), New scan dialog (scanners, targets,
  intensity, gate preview), stop / delete, detail page with skipped reasons and raw
  results download (`/api/scans/[id]/results/[fileId]`).
  Verified on the real DB: added localhost:3100 (Juice Shop) + example.com, ran Web
  surface + Port scan from the UI -> 6 real risks, health 221 / B on the dashboard,
  example.com skipped by the gate.
  Still open in item 4: tool resolver (local binary / Docker / unavailable) and
  subfinder. Still open in item 10: Scheduled tab and schedule-from-dialog.
- 2026-11-02: merged Jay's origin/main a2b6cbe (UI redesign: radar surface map, stage
  rail, findings-first results, deeper ink palette, cyan-to-sky accent, survey grid,
  motion + reduced-motion). His page lives at `/quick-scan` (own header replaced by a
  label + status-pill bar since the sidebar carries the logo). His palette is the
  global theme; grade / closed tokens retuned to it. His design language is now in the
  shared kit: gradient primary buttons, gradient page titles, mono label headings,
  Chip / Tag badge styles, glowing severity edges, rising rows, glass sidebar and
  cards, `components/ui/severity-donut.tsx` (dashboard risks panel) and
  `components/ui/segmented.tsx` (dashboard period, New scan intensity).
- 2026-11-03: item 11 done. Risks page on real data: filters (status, severity,
  accepted, scanner, target, tag, search), group by risk or target, drawer
  (description, solution, references, evidence, history from the audit log),
  accept / un-accept with a reason (recomputes health), acceptance rules tab
  (create, enable/disable, delete; rules re-applied to open risks immediately via
  `lib/services/acceptance.ts`), CSV export `/api/risks/export` (same filters,
  formula-injection safe). Pure logic in `lib/domain/risk-table.ts`.
- 2026-11-03: item 12 done except scheduled reports. Builder (name, format, targets /
  tags, severities, accepted / closed, sections) -> frozen snapshot
  (`lib/domain/report.ts`) -> printable report `/reports/[id]` (cover, executive
  summary, coverage, target breakdown, risk details, accepted risks; light print
  theme for PDF), JSON / CSV downloads `/api/reports/[id]/download`, history, delete.
  Target drawer "Generate report" preselects the target.
- 2026-11-03: Integrations page is a labelled PREVIEW (item 14 still open): cards and
  setup dialogs for email, Slack, Teams, PagerDuty, webhooks, Jira, AWS, Azure; save
  and test are disabled and nothing is stored or sent.
- 2026-11-03: merged Amaan's origin/main fce5f79 (opt-in proxy via PROXY_URL /
  PROXY_LIST, WAF / block detection). Flagged to Kartik: proxy *rotation* reads as
  block evasion; nothing new builds on it.
- 2026-11-03: item 3 done. `lib/domain/authorization.ts` (tiers: 0 passive, 1
  attested, 2 DNS-verified or local; domain scopes cover subdomains, CIDR covers
  contained ranges; TXT token check), `lib/services/authorization.ts` (attest, issue
  / check DNS token with injectable resolver, revoke, all audit-logged), scan gate now
  uses the records, quick-scan routes (`/api/scan/probe|ports|fingerprint|analysis|
  nuclei`) refuse any unauthorized host with 403 via `lib/scans/route-guard.ts`
  whatever `activeAllowed` says. UI: Authorization panel in the target drawer,
  badge column in the targets table, New scan dialog uses server authorization.
  Verified: 403 for an unauthorized host, 200 for local, real DNS TXT lookup, attest
  flow in the browser (demo DB, to keep the real audit log honest).
- 2026-11-03: item 5 done. `lib/scans/checks/`: `tls.ts` (pure Node: expiry, trust,
  hostname, key size, legacy TLS 1.0/1.1), `email.ts` (SPF / DMARC), `takeover.ts`
  (dangling CNAMEs to ~25 hosted services, target + discovered subdomains),
  `js-secrets.ts` (10 key formats incl. Supabase service_role JWT, masked storage,
  source maps), `zap.ts` (Docker baseline / full, JSON report parsing; work dir under
  data/zap-runs because Docker Desktop doesn't share the OS temp dir).
  `lib/scans/tools.ts` (no-shell command runner, Docker / image checks) covers the tool
  resolver part of item 4 (subfinder still not wired). New scan dialog greys out
  Docker scanners when Docker or the image is missing. Content checks use an undici
  agent that accepts bad certificates (TLS issues are reported by the TLS scanner).
  Live-tested on the real DB (fixture target removed afterwards).
