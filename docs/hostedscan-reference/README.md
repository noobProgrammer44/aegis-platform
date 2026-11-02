# HostedScan reference (feature research)

Notes on HostedScan (hostedscan.com), the product whose dashboard Aegis is matching
feature-for-feature. Gathered 2026-11-02 from the public site, docs.hostedscan.com,
the API reference and help.hostedscan.com. Screenshots of the logged-in dashboard
taken from their marketing pages live in `screens/` (gitignored: they are
HostedScan's images, kept locally only as a layout reference).

Aegis copies the information architecture and feature set. It keeps its own name,
logo, colours and copy.

## Navigation (left sidebar)

Logo + collapse button, workspace/account switcher, then:
Dashboard, Targets, Scans, Risks, Reports, Integrations, Settings.
Bottom: Support, API Docs (external), Help Center (external).

## Dashboard (`screens/v3_dashboard-large.png`)

- Header: "Dashboard" + period selector ("Last year"), pill "0 scans in progress |
  20 scans scheduled", primary "+ New Scan" button.
- Health Score card: semicircle gauge (green / yellow / red bands, needle), grade
  badge (B) + label ("Fair Health"), "About your score": trend vs last month,
  "Top 3 issues dragging down your score", educational links.
- Risks detected (Total N): four tall tiles Critical / High / Medium / Low with big
  numbers (tinted backgrounds), below them Accepted (green) and Closed (grey) bars.
- Three columns: Recent Scans (scan type, target URL, age, Report link), Recent
  Risks (severity dots, scanner, risk title, target label), Discovered Domains
  (count badge; "vpn.acme-corp.com via acme-corp.com"; See all targets).
- Insight cards (`v3_home_mitigate-security-vulnerabilities.png`): Most Vulnerable
  Target (POOR 98), Most Critical Vulnerability (age in days), Most Frequent
  Vulnerability (N encounters at M targets).
- Charts (`v3_continuous-security-monitoring...png`): Risks Overview vs N days ago
  (count + "1 NEW" deltas), Open Risks stacked bars per severity + Assets line on a
  second axis, Exposure Window stacked bars (< 30 days, 30-90 days, > 90 days).

## Targets / Assets (`v3_vulnerability-management_hero...png`)

- "Assets" title, "Add Asset", split "New Scan" button.
- Toolbar: Grouping (None / tag), Search, Sort by (Health Score), Filters (count).
- Table: expand chevron, ASSET (host small, label bold, tag chips), HEALTH (grade
  chip), DISCOVERED (count chip), SOURCE, LAST SCANNED.
- Target Overview panel: See all risks, "Scan this target again", "Generate Report";
  stat strip (Risks, Critical, High, Medium, Low, No longer found); tabs Risks /
  Recent Scans / Trends / Metadata; risk rows with severity bars + first/last
  detected; "Filter by risk"; Target Health Score gauge.
- Add target (`v3_platform_platform-power-map-attack-surface.png`): quick sources
  (Internal scanning, IP scan, AWS, Azure, More), Discovered Domains list, form:
  Target (IPv4, Domain, URL or Public CIDR), Tags (up to 5), Label, "Add Target".

## Scans

- New scan picker (`v3_platform_platform-solutions-target.png`): stacked scanner
  cards with checkbox, scanner name small caps + scan name; ZAP has Passive "Basic
  scan" vs "Passive & Active" "Full scan" radio; OpenVAS Network Vulnerability Scan;
  Nuclei General Vulnerability Scan; Port Scan. Footer: "Schedule Scan" / "Run Scan".
- Schedule (`v3_usecases_solutions-scheduling.png`): One Time / Daily / Weekly /
  Monthly / Quarterly / Custom; "At a future time" + datetime with timezone;
  "Receive inbox notifications" email chips.
- Scan object: type, state (QUEUED, RUNNING, SUCCEEDED, FAILED, OVER_LIMIT,
  STOPPING, STOPPED), progress 0-100, risks {new_open, still_open, closed},
  results files, requested / resolved / skipped targets, scheduled_by, report_id.
- Scan types: DOMAIN_TAKEOVER, NMAP, NMAP_UDP, NUCLEI, OPENVAS, OWASP_ZAP (passive),
  OWASP_ZAP_ACTIVE, SSLYZE, NESSUS, plus imported DEPENDABOT / SNYK.

## Risks

- Risk: target, label, tags, status OPEN/CLOSED, first/last detected, is_accepted,
  accepted_by rules, risk_definition {scan_type, title, threat_level LOW..CRITICAL,
  description, solution, references, cvss, additional_info}.
- Closed = the latest scan no longer detects it. Accepted = deliberately
  suppressed (open by design, false positive, low priority). Accepted risks are
  excluded from the health score.
- Advanced acceptance rules: Mongo-style query across targets/risks, e.g. accept
  ports 80/443 on targets tagged webserver, accept LOW risks from one scanner.
- Export to CSV.

## Health score (docs: health-score-modeling)

- 0-1000, lower is better. Grades: A 0-200, B 201-400, C 401-600, D 601-800,
  F 801-1000.
- Highest open severity sets the tier floor: LOW 10, MEDIUM 150, HIGH 350,
  CRITICAL 700. More findings of that severity push toward the top of the tier with
  diminishing returns; lower severities add a capped lift inside the tier.
- Only open, non-accepted findings count.

## Reports (`v3_continuous-security-monitoring...png`, `report_sample_*.png`)

- Tabs: Create a Report / Scheduled Reports. Name, Report Format (PDF...),
  Schedule (Weekly), date/time. "Which targets should be included?" (All Targets),
  "Which risks should be included?" (Risk Threat Level matching ..., Add Risk Filter).
- PDF: cover, 1.0 Executive Summary (Critical/High/Medium/Low/Accepted tiles,
  percentage bar), 1.2 Report Coverage (targets, active web, passive web, network,
  SSL/TLS, open TCP/UDP ports), target breakdown, per-scanner sections, 3.3
  Vulnerability Details (severity bars, affected targets, last detected,
  Description, Solution). White-label branding on Professional plan.

## Integrations / settings / API

- Email alerts (NEVER / ON_CHANGES / ALWAYS), Slack, Jira, AWS + Azure target
  import, webhooks (Premium), REST API with keys (`/v1/targets`, `/scans`,
  `/scans/scheduled`, `/risks`, `/reports`, `/results`), SAML SSO, workspaces
  (data, API keys and webhooks isolated per workspace), white-label branding,
  scanner IP list, QoD threshold.
- AI: llms.txt + agent skills for coding agents.

## Plans (for context)

Basic $39/mo, Premium $109/mo, Professional $189/mo (5 targets each), Flex from
$2,500/yr. Premium adds authenticated scans, internal scanning, API + webhooks, CSV
export; Professional adds white-label, SSO, workspaces, Nessus.
