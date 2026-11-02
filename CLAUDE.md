# Aegis — External Attack Surface Assessment

> **On branch `aegis-platform`?** Read **`docs/handoff/CONTEXT.md`** first. It holds the
> full working context: setup, how to run everything, architecture, scanners, rules,
> gotchas, what's done and what's next. Then `docs/LOOP-PLAN.md` and
> `docs/BRANCH-STATUS.md`. On that branch, Juice Shop runs on **3100** and Aegis on
> **3001**, and the authorization tiers in the code are described in CONTEXT.md section 8.

Aegis is an External Attack Surface Assessment (EASS) tool: given an authorized
target scope, it enumerates the externally reachable surface, fingerprints what's
running, probes for exposures, and produces a human-readable risk summary. Built
on **Next.js 15 (App Router) + TypeScript + Tailwind v4**, Node-first, with
**nuclei orchestrated via Docker** for deep vulnerability detection.

> ⚠️ **Authorized use only.** Aegis performs active reconnaissance and
> vulnerability scanning. Only ever run it against assets you own or have explicit
> written authorization to test. See the authorization model below — it is a
> hard gate, not a guideline.

## Architecture: 4-stage recon pipeline

The engine runs as a staged pipeline. Each stage narrows and enriches the data
from the previous one. Stages are concurrency-bounded with **`p-limit`** so a
single run never stampedes a target.

1. **Discovery** — Expand the authorized scope into candidate assets: subdomain
   enumeration, DNS resolution, CIDR/host expansion, and passive OSINT. Output:
   a deduplicated set of candidate hosts/endpoints. *(Passive-only by default —
   no packets to the target beyond DNS.)*

2. **Live probe** — Determine which candidates are actually reachable. HTTP(S)
   probing across common ports/schemes, following redirects, capturing status
   codes, response headers, TLS metadata, and server banners. Output: the set of
   **live** endpoints with their raw HTTP metadata.

3. **Crawl / fingerprint** — For each live endpoint, fetch and parse content with
   **`cheerio`**, extract links/forms/script sources, and identify technologies
   with **`simple-wappalyzer`** (maintained, browserless Wappalyzer-rule engine
   that matches on HTML + headers + script srcs + cookies + meta). Output: a
   technology/stack fingerprint and an expanded endpoint map per host.
   - **Note for SPAs:** a bare app shell (e.g. an Angular/React root page) often
     exposes *no* fingerprints at `/`. Fingerprinting must also fetch linked JS
     bundles (`main.js`, etc.) to see the real stack. This is expected behavior,
     not a detector failure.

4. **Surface analysis** — Correlate everything into findings: exposed
   technologies and versions, risky headers/misconfigurations, interesting
   endpoints, and — for in-scope targets at the right authorization tier — run
   **nuclei** for templated vulnerability detection (see below). Output: a
   structured findings set that feeds the AI summary.

## Node-first, with nuclei via Docker

Stages 1–3 and the orchestration layer are **pure Node/TypeScript** — no external
binaries required for the baseline recon. Deep, templated vulnerability detection
is delegated to **nuclei**, run as a **Docker container** (`projectdiscovery/nuclei:latest`)
rather than a local install. This keeps the scanner version pinned/reproducible,
sandboxes it from the host, and avoids a Go toolchain dependency.

Aegis shells out to Docker (e.g. `docker run --rm projectdiscovery/nuclei:latest -u <target> -json ...`),
streams nuclei's JSON output back into the pipeline, and merges it into the
stage-4 findings. nuclei only runs for targets that clear **Tier 3** authorization.

**Scoped templates for speed.** The scan does **not** load the full ~17k template
set (which takes minutes and times out). The default set is `-severity
medium,high,critical` + `-tags exposure,misconfig,exposed-panels,default-login` +
`-exclude-tags fuzzing,dos,intrusive` (~1.4k templates, finishes in ~1–2 min).

The `cve` tag (~4k more templates) is **opt-in via the "Deep CVE scan" UI toggle**
(`deepCve` in the API body). Its exploit payloads can **crash fragile single-host
targets** — Juice Shop SIGSEGVs under it — so it's meant for robust real targets,
not the local demo. `max-host-error`, `rate-limit`, and `concurrency` are
locality-based: gentler for localhost (which is fragile), higher for remote hosts.

**One-time template warm-up (do this before your first scan).** Templates live in
a persistent Docker volume (`aegis-nuclei`) so they download once, not per run. The
scan uses `-disable-update-check`, so pre-download the templates first:

```bash
docker run --rm -v aegis-nuclei:/root projectdiscovery/nuclei:latest -update-templates
```

Re-run that occasionally to refresh templates. Without it (on a fresh machine) the
first scan has no templates and returns no nuclei findings.

## Authorization model (3 tiers)

Authorization is enforced per target **before** any stage touches it. Higher tiers
are strictly more invasive and require stronger proof of authorization. A target
may never be escalated past the tier it was authorized at.

| Tier | Scope of activity | What it gates | Requirement |
|------|-------------------|---------------|-------------|
| **Tier 1 — Passive** | OSINT & DNS only; no direct packets to target assets | Discovery | In-scope declaration |
| **Tier 2 — Active (non-intrusive)** | Live probing, crawling, fingerprinting | Live probe + crawl/fingerprint | Confirmed ownership / scope attestation |
| **Tier 3 — Intrusive** | Templated vulnerability scanning (nuclei) | Surface analysis vuln scan | Explicit written authorization + rate limits |

The pipeline checks a target's granted tier at each stage boundary and refuses to
execute a stage above that tier.

## AI summary (OpenRouter)

After stage 4, the structured findings are sent to an LLM via **OpenRouter** to
produce a prioritized, human-readable executive summary (risk narrative,
notable exposures, suggested next actions). The key lives in `.env.local` as
`OPENROUTER_API_KEY` (gitignored). The AI layer is **summary/triage only** — it
never decides authorization and never triggers scanning.

## Port scan (Stage 2b)

Between live probe and fingerprint, Aegis runs a **pure-Node TCP-connect scan** over
~90 common ports per live host (`lib/recon/ports.ts`, `POST /api/scan/ports`). No
raw sockets, Docker, or root — each port is a `net.Socket` connect test, bounded by
p-limit and a per-port timeout. Open ports become findings (**INFO**; **HIGH** for
exposed data stores / admin services like MySQL, Redis, MongoDB, Elasticsearch).
Open web ports (80/443/3000/8080/8443/…) are **fed back through probe + fingerprint**
so services on non-standard ports are checked too. It's an ACTIVE stage behind the
same authorization gate as the others — never on passive-only scans.

## Scan intensity (low & slow)

A single `scanIntensity` setting controls how hard every active stage hits the
target (`lib/recon/intensity.ts`), applied consistently across probe, port scan,
fingerprint, and nuclei. Default **polite**. Chosen from a dropdown in the UI,
passed to every active route, and logged at the start of each scan.

| Level | Node concurrency | Inter-request delay | nuclei rate / concurrency |
|---|---|---|---|
| **Polite** (default) | 4 | 250 ms | 20 / 10 |
| **Normal** | 12 | 50 ms | 60 / 20 |
| **Aggressive** | 30 | 0 ms | 150 / 30 |

Polite is slow, stealthy, and kind to the target; aggressive is fast (and can
overwhelm fragile hosts). Scan speed visibly changes with the setting.

## Scan reports

Every completed scan is persisted as JSON to **`./scans/<target>-<timestamp>.json`**
(gitignored — may contain sensitive target data) and exported as a clean Markdown
pentest deliverable via `POST /api/scan/report` (`lib/report/markdown.ts`): title,
scope + authorization note, executive summary (risk score + severity counts),
findings grouped by severity, open-ports table, detected technologies/versions, and
a methodology section. The UI's **Download report** button saves it as a `.md` file.

## Proxy support (anti-block, opt-in)

Optional, env-configured, **off by default**. Set `PROXY_URL="http://host:port"`
(single) or `PROXY_LIST="http://a:1,socks5://b:2"` (rotated round-robin) in
`.env.local`. Supports HTTP(S) and SOCKS4/5 (`lib/recon/proxy.ts`). When set, the
**active** stages route through it: probe + fingerprint via an undici dispatcher,
the port scan via SOCKS / HTTP-CONNECT, and nuclei via its native `-proxy` flag
(which rotates the list). Only active (authorization-gated) stages use the proxy,
and its use is logged at stage start — so proxy use sits behind the auth tier.
Passive discovery never uses it.

## WAF / block detection

Active stages detect when a target is fronted by a WAF/CDN or is throttling the
scan (`lib/recon/waf.ts`): vendor signatures in headers (Cloudflare `cf-ray`,
Akamai, CloudFront, Fastly, Sucuri, Imperva, F5, Vercel, Netlify), block status
codes (429/503), challenge-page bodies, and nuclei's host-unresponsive skip. When
detected it emits an **INFO / recon** finding — *"Target behind WAF/CDN — active
scan depth limited"* — naming the signal, surfaced in the findings table like any
other finding. The deep (nuclei) stage degrades gracefully to a **`partial`**
status (not a hard error); the UI labels it *"Deep scan partial — target
throttled/blocked."* A partial deep scan never discards the other stages' findings
or the risk score.

## Tech stack & layout

- **Framework:** Next.js 15.5.x, App Router (`app/`), TypeScript, Tailwind CSS v4, ESLint
- **Runtime:** Node (dev machine on v24; engines require Node ≥ 20)
- **Key deps:** `p-limit` (concurrency bounding), `cheerio` (HTML parse/crawl),
  `simple-wappalyzer` (tech fingerprinting)
- **External:** Docker — `projectdiscovery/nuclei:latest` (scanner),
  `bkimminich/juice-shop` (local test target)

## Dev commands

```bash
npm run dev     # Next dev server (Turbopack)
npm run build   # production build
npm run start   # serve production build
npm run lint    # ESLint
```

> ⚠️ **Port conflict:** the local test target (OWASP Juice Shop) runs on
> **port 3000**, which is also Next.js's default dev port. Run the app on another
> port to avoid a clash, e.g. `npm run dev -- -p 3001` (or stop Juice Shop first).

### Local test target (OWASP Juice Shop)

```bash
docker run -d -p 3100:3000 --name aegis-juiceshop bkimminich/juice-shop
# → http://localhost:3100  (3000 clashes with the Next dev server)
docker rm -f aegis-juiceshop   # tear down
```

Juice Shop is intentionally vulnerable and is the only target to point intrusive
(Tier 3 / nuclei) scanning at during development.
