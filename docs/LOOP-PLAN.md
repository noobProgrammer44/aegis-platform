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
- [ ] 1. Tooling: vitest + test script, `better-sqlite3`, `zod`; `lib/db` schema +
      migrations + repositories (targets, scans, risks, schedules, reports, rules,
      authorizations, audit log, webhooks, api keys, settings, notifications).
- [ ] 2. Domain logic with tests: target parsing (IPv4 / domain / URL / CIDR),
      health score (0-1000, A-F, tier floors + diminishing returns), risk lifecycle
      (new_open / still_open / closed / reopened), acceptance rule matcher,
      schedule next-run.
- [ ] 3. Server-side authorization service (tiers, attest, DNS TXT verify, local
      auto-auth, audit log) and enforce it in the existing `/api/scan/*` routes.

### Scan engine
- [ ] 4. Scanner framework + tool resolver (local binary / Docker / unavailable)
      and adapters for the existing pipeline: Web surface (probe + fingerprint +
      headers + TLS expiry + exposed paths), Nuclei, Subdomain discovery (crt.sh +
      subfinder) feeding "Discovered domains".
- [ ] 5. More scanners: Nmap TCP port scan, TLS/SSL (sslyze, Node fallback),
      Email security (SPF / DMARC / MX), Domain takeover (dangling CNAME), JS
      secrets + source maps ("vibe-code leaks"), OWASP ZAP baseline + full (Docker).
- [ ] 6. Scan runner + queue (QUEUED -> RUNNING -> SUCCEEDED / FAILED / STOPPED,
      progress, stop), risk merge + health recompute, events; scheduler for
      scheduled scans via `instrumentation.ts`.

### UI
- [ ] 7. App shell: sidebar (Dashboard, Targets, Scans, Risks, Reports,
      Integrations, Settings, Audit log; Quick scan, API docs, Help), collapse,
      shared UI kit (buttons, tiles, chips, drawer, modal, table, gauge); move the
      old single page to `/quick-scan`.
- [ ] 8. Dashboard: period selector, scans-in-progress / scheduled pill, New Scan,
      health gauge + about-your-score, severity tiles + accepted / closed, recent
      scans / risks / discovered domains, insight cards.
- [ ] 9. Targets: table (grouping, search, sort, filters, tags, grade, discovered,
      source, last scanned), Add target (target / tags / label, bulk paste),
      discovered domains -> add, target drawer (stats, tabs, gauge, rescan,
      report), authorization panel (attest / DNS verify).
- [ ] 10. Scans: list (state, progress, type, targets, new / open / closed, stop,
      delete), New Scan modal (scanner cards, passive vs full, target / tag
      selection, run now or schedule, email chips), scan detail with live
      progress + raw results download, Scheduled tab.
- [ ] 11. Risks: table (filters by level / status / accepted / scanner / target /
      tag, search, group by title or target), risk drawer (description, solution,
      references, CVSS, evidence, history), accept / unaccept with reason,
      acceptance rules editor, CSV export.
- [ ] 12. Reports: builder (name, format HTML-PDF / JSON / CSV, targets filter, risk
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
