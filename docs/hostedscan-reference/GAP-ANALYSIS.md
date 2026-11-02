# Aegis vs HostedScan: what's missing

From a read-only walk through a live HostedScan account (Premium trial) on
2026-11-03. Screenshots are kept locally in `screens/app/` (gitignored).
Priority: **P1** = visible gap in a screen we already have; **P2** = new capability;
**P3** = nice to have or out of scope.

## Risks (biggest gap)

| HostedScan | Aegis today | Priority |
|---|---|---|
| Rows expand **inline** (chevron), not a side panel | side drawer | P1 |
| Row: threat **bars** (1–4 filled), scanner name above title, **OWASP Top 10** chip, CVSS + QoD for network scans, First / Last detected, status pill, **Accept Risk** button in the row | severity badge, title, target, last detected; accept only in drawer | P1 |
| Detail: big title, **Formatted / Table / JSON** toggle | single formatted view | P1 |
| Detail metadata grid: Severity, Status, Scan, **OWASP Top 10 (linked)**, **CWE (linked)**, **WASC** | description, solution, references, evidence key/values | P1 |
| **Instances (N)** tab: every affected URL, each expandable to **request headers, response headers, response body** | one host; ZAP URLs flattened into the description | P1 |
| **References (N)** tab | references list | P1 |
| Filter side panel: CVE ID, hostname, label, OS, risk, scan type, source, source type, status, … | inline filters (status, severity, accepted, scanner, target, tag, search) | P2 |
| Pagination (rows per page) | none | P2 |

## Scans

| HostedScan | Aegis today | Priority |
|---|---|---|
| **New Scan is a 4-step page**: Select Scans → Select Targets → Configure → Review, with a help side panel | single modal | P1 |
| Scanner cards with capability tags (WEBSITES, CVES, SSL CERTIFICATES, …) and an info icon; ZAP card has Passive vs Active+Passive radio with a warning | checkbox cards with passive / active chip | P1 |
| Select Targets step: table with Select all, **Select by tag**, filters, **Create Target inline** | checkbox list | P1 |
| **Configure step: schedule** (One time Now / date, Daily, Weekly, Monthly, Quarterly, Custom) + **email notification** (all members / custom / none) | none (scheduler backend exists, no UI) | P1 |
| **Scheduled Scans tab**: name, targets (or "All targets"), schedule, scan types, last run, next run, email policy, View Scans, row menu | none | P1 |
| Scan rows expand inline: **Risks overview vs previous scan** ("6 NEW" per severity, no longer found), tabs **Scan Snapshot / Crawled URLs / Metadata**, filter by risk | separate detail page with new / still open / closed counts | P1 |
| **Report ▾ per scan**: HostedScan PDF report + raw scanner output as **PDF / HTML / JSON / XML** + artifacts (**Crawled URLs**, **Scan Stats**) | one JSON results file | P1 |
| Risks column as per-severity dot counts | new / open / closed numbers | P2 |
| Nmap TCP full range (0–65535) and **Nmap UDP** | TCP connect, ~90 common ports | P2 |
| **OpenVAS** network vulnerability scan (CVSS, QoD) | not built (multi-GB feed) | P3 |
| Nessus / Greenbone enterprise | n/a (commercial) | P3 |
| Authenticated web scanning, API scanning (help links) | none | P3 |

## Dashboard

| HostedScan | Aegis today | Priority |
|---|---|---|
| **Trends**: Open Risks (stacked bars per severity + assets line), **Exposure Window** (<30, 30–90, >90 days), Health Score (good / fair / poor + assets), Week / Month / Year, filters | none (daily snapshots are already recorded) | P1 |
| Recent scans with a **Report** link each | no report link | P2 |
| **Getting started** checklist in the sidebar (review your risks, generate a report) | none | P3 |
| Colourful tiles: Critical purple, High red, Medium orange, Low yellow, Accepted green, Closed grey | Aegis dark tiles (keep our identity) | — |

## Targets

| HostedScan | Aegis today | Priority |
|---|---|---|
| Row **expands inline** with Risks Overview, "See all risks", "Scan this target again", "Generate Report" | drawer with the same actions | P2 |
| Detail tabs: Risks, Recent Scans, **Discovered Domains**, **Trends**, Metadata; "Filter by risk" | Risks, Recent scans, Metadata | P1 |
| Columns: **Created**; row "…" menu; pagination; Filters panel | grouping / search / sort / grade / tag filters | P2 |

## Reports

| HostedScan | Aegis today | Priority |
|---|---|---|
| **Preview with a live count** ("1 targets, 9 risks") before generating | count shown only after generating | P2 |
| **Download as PDF / CSV / HTML** directly | print-to-PDF, JSON, CSV | P2 |
| **Scheduled Reports** tab | none | P1 |
| Filters via "Add a filter", sections as a multi-select dropdown | checkboxes | P3 |

## Settings / integrations / platform

| HostedScan | Aegis today | Priority |
|---|---|---|
| Settings sections: General (org name, **time zone**, security badge, delete account), Scanners (OpenVAS QoD threshold, internal-scan retention, custom configs), Billing, Team, Integrations, **API & Webhooks**, SAML SSO, White Label, Workspaces, User Settings | placeholder page | P1 (General, Scanners, API & Webhooks) |
| **API keys** (create / revoke) and **webhook endpoints** (https only) with delivery logs | none | P1 |
| Target integrations: AWS, Azure, DigitalOcean, Linode, Google Cloud, GitHub Dependabot, Snyk | preview cards for AWS, Azure | P3 |
| Account integrations: **Jira, Microsoft Teams, Slack**, Vanta | preview cards (Slack, Teams, Jira, email, PagerDuty, webhooks) | P2 (Slack / Teams / Jira real) |
| **Internal Networks** (agent-based internal scanning) | none | P3 |
| Organization switcher, team members, roles | single local workspace | P3 |

## Proposed build order

1. Risks: inline expansion, threat bars, OWASP / CWE / WASC grid, Formatted / Table / JSON, **Instances with request / response** (ZAP's `traditional-json-plus` report carries them), references.
2. New Scan wizard (4 steps) with schedule + email options, and the Scheduled Scans tab.
3. Scan rows: inline expansion with "vs previous scan", Crawled URLs, Report ▾ with raw outputs.
4. Dashboard and target Trends charts (Open Risks, Exposure Window, Health Score).
5. Settings: General (time zone), Scanners, API keys + webhooks (real), then Scheduled Reports.
6. Then the P2 / P3 items.
