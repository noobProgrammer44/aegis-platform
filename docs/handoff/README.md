# Aegis handoff: start here

Last updated 2026-11-02. This folder lets someone new (Amul, or a fresh Claude Code
session) continue the build without the original chat.

## Read in this order

1. `docs/handoff/README.md` (this file): current state and how to resume.
2. `docs/LOOP-PLAN.md`: the build checklist, decisions, and progress log. Work
   always continues from the first unchecked item.
3. `docs/handoff/session-context.md`: research and reasoning from the planning
   chat (competitor landscape, why HostedScan is the model, open suggestions).
4. `docs/hostedscan-reference/README.md`: HostedScan's dashboard broken down
   screen by screen, with the data model, health score maths and report layout.
   Screenshots are in `docs/hostedscan-reference/screens/` locally only
   (gitignored). Amul's copy is in the separate handoff folder.
5. `CLAUDE.md` and `BUILD-PLAN.md`: the original architecture and phase plan.
6. `Aegis-Stakeholder-Outline.md`: the stakeholder document.

## Where things stand

**Done on `main` (before this work):** Phases 1-6 of `BUILD-PLAN.md`. The page is a
single client-side flow in `app/page.tsx`: discovery (crt.sh + DNS), live probe,
fingerprint (simple-wappalyzer + JS bundles + error pages), analysis (security
headers, TLS expiry, exposed paths, version hints), and nuclei via Docker with
streamed findings.

**Gaps found when the code was read:**
- The authorization gate is client-side only. The browser sends
  `activeAllowed: true` and every `/api/scan/*` route trusts it. Phase 7 is not
  built.
- Nothing is saved. Targets, scans and findings disappear on refresh.
- No AI summary (Phase 8) and no SSE progress or dashboard (Phase 9).

**Done on branch `feat/hostedscan-parity` (this handoff commit):**
- `docs/LOOP-PLAN.md`: 18-item plan to reach HostedScan feature parity.
- `docs/hostedscan-reference/`: research notes.
- `types/aegis.ts`: domain types (Target, Scan, Risk, ScheduledScan,
  AcceptanceRule, Authorization, AuditEntry, DiscoveredDomain, Report, Webhook,
  ApiKey, Notification, Workspace, HealthSnapshot).
- `lib/db/migrations.ts`: full SQLite schema (workspace-scoped from day one).
- `lib/db/client.ts`: better-sqlite3 connection, migrations via `user_version`,
  default workspace, id/JSON helpers.
- Dependencies added: `better-sqlite3`, `zod`, `vitest`, `@types/better-sqlite3`.
- `npx tsc --noEmit` passes.

**Item 1 is done** (data layer): `lib/db/repos/*` has one repository per table,
all workspace-scoped, plus `npm test` (vitest) with repository tests on
`openDb(":memory:")`. Next up is item 2 (domain logic with tests). The checklist
in `docs/LOOP-PLAN.md` is always the source of truth for what's next.

## Machine setup (already done on Kartik's Mac; repeat on a new machine)

```bash
# ProjectDiscovery tools from GitHub (needs Go 1.24+); binaries land in ~/go/bin
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

brew install nmap            # Windows: nmap.org installer
pipx install sslyze
docker pull bkimminich/juice-shop
docker pull zaproxy/zap-stable
npm install
```

Gotchas:
- On macOS a Python package also installs a CLI called `httpx`. The scanner tool
  resolver must prefer `~/go/bin/httpx` (or check that `httpx -version` mentions
  projectdiscovery) rather than trusting PATH order.
- Port 3000 was already taken on Kartik's Mac by another Node app. Run Juice
  Shop on another port (`docker run -d -p 3100:3000 --name aegis-juiceshop
  bkimminich/juice-shop`) and Aegis on 3001 (`npm run dev -- -p 3001`).
- The teammate machine in `CLAUDE.md` is Windows. Every scanner adapter must
  handle a missing binary by falling back to Docker or reporting "unavailable".

## How to resume with Claude Code

Open the repo, check out the branch, and paste this:

```
/loop AEGIS BUILD LOOP (self-paced: don't stop till every item in docs/LOOP-PLAN.md is done).
Repo: this folder, branch feat/hostedscan-parity, commit locally after each finished
item, never push without asking. Each tick: (1) read docs/handoff/README.md,
docs/LOOP-PLAN.md and docs/hostedscan-reference/README.md; (2) pick the next unchecked
item and build it fully (read code before editing, follow CLAUDE.md + BUILD-PLAN.md,
Next.js 15 App Router + TS + Tailwind v4, immutable patterns, files under 400 lines,
no console.log); (3) verify with npx tsc --noEmit, npm run lint, npm test,
npm run build, and for UI items load the page on the dev server (port 3001) and check
it renders; (4) tick the item in docs/LOOP-PLAN.md with a one-line note in the
progress log and commit; (5) when every item is checked and the final review is
clean, stop the loop and report. Active scans only against local Juice Shop or
attested / DNS-verified targets.
```

Without `/loop`, the same text works as a normal prompt. It will then finish one
item per message.
