"use client";

import { useState } from "react";
import type {
  Finding,
  Fingerprint,
  LiveHost,
  NucleiEvent,
  NucleiResult,
  OpenPort,
  ScanResult,
  Severity,
  Subdomain,
} from "@/types/recon";
import {
  dedupeFindings,
  riskLevel,
  riskScore,
  riskScoreByHost,
  severityCounts,
  sortFindings,
} from "@/lib/recon/score";
import {
  DEFAULT_INTENSITY,
  INTENSITY_PROFILES,
  type ScanIntensity,
} from "@/lib/recon/intensity";

const DNS_RESOLVE_CAP = 75;

type TargetMode = "direct" | "domain";

type ScanState = {
  mode: TargetMode;
  domain: string; // the target: a host (direct) or a domain (enumeration)
  startedAt: string;
  subdomains: Subdomain[];
  liveHosts: LiveHost[] | null; // null = probe not run
  probeError: string | null;
  openPorts: OpenPort[] | null; // null = port scan not run
  portFindings: Finding[]; // merged into the findings view + risk score
  portsError: string | null;
  fingerprints: Fingerprint[] | null; // null = fingerprint not run
  fingerprintError: string | null;
  findings: Finding[] | null; // null = analysis not run (Stage 4a)
  findingsError: string | null;
  nuclei: NucleiResult | null; // null = nuclei not run (Stage 4b)
  nucleiError: string | null;
  report: { markdown: string; savedAs: string | null } | null;
  reportError: string | null;
};

/**
 * Decide whether the input is a single host to probe directly, or a registrable
 * domain to enumerate. Direct if it's a full URL, has a port, is localhost, an IP,
 * or a single-label host; otherwise a domain.
 */
function classifyTarget(raw: string): { mode: TargetMode; host: string } {
  const input = raw.trim();
  const isUrl = /^https?:\/\//i.test(input);

  let host = input;
  if (isUrl) {
    try {
      host = new URL(input).host; // includes port if present
    } catch {
      /* fall back to raw input */
    }
  } else {
    host = input.split("/")[0]; // drop any path
  }

  const hostname = host.replace(/:\d+$/, "");
  const lower = hostname.toLowerCase();
  const hasPort = /:\d+$/.test(host);
  const isLocalhost = lower === "localhost" || lower.endsWith(".localhost");
  const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const isIPv6 = hostname.startsWith("[") || (hostname.match(/:/g)?.length ?? 0) >= 2;
  const isSingleLabel = hostname.length > 0 && !hostname.includes(".");

  const direct =
    isUrl || hasPort || isLocalhost || isIPv4 || isIPv6 || isSingleLabel;
  return { mode: direct ? "direct" : "domain", host: direct ? host : hostname };
}

async function postJSON<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error((data as { error?: string })?.error ?? `Request failed (${res.status})`);
  }
  return data as T;
}

const errMsg = (e: unknown) =>
  e instanceof Error ? e.message : "Something went wrong.";

export default function QuickScanPage() {
  const [domain, setDomain] = useState("");
  const [activeScan, setActiveScan] = useState(false);
  const [deepCve, setDeepCve] = useState(false);
  const [scanIntensity, setScanIntensity] =
    useState<ScanIntensity>(DEFAULT_INTENSITY);
  const [loading, setLoading] = useState(false);
  const [probing, setProbing] = useState(false);
  const [scanningPorts, setScanningPorts] = useState(false);
  const [fingerprinting, setFingerprinting] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [scanningNuclei, setScanningNuclei] = useState(false);
  const [nucleiProgress, setNucleiProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanState | null>(null);

  const canScan = domain.trim().length > 0;
  const busy =
    loading ||
    probing ||
    scanningPorts ||
    fingerprinting ||
    analyzing ||
    scanningNuclei;
  const liveClass = classifyTarget(domain);

  // Merge analysis + nuclei + port findings into one deduped, severity-sorted set.
  function mergedFindings(state: ScanState): Finding[] {
    return sortFindings(
      dedupeFindings([
        ...(state.findings ?? []),
        ...(state.nuclei?.findings ?? []),
        ...state.portFindings,
      ]),
    );
  }

  function buildScanResult(state: ScanState): ScanResult {
    const merged = mergedFindings(state);
    const stagesRun = ["Discovery"];
    if (state.liveHosts) stagesRun.push("Live probe");
    if (state.openPorts) stagesRun.push("Port scan");
    if (state.fingerprints) stagesRun.push("Fingerprint");
    if (state.findings) stagesRun.push("Analysis");
    if (state.nuclei) stagesRun.push("nuclei");
    return {
      target: state.domain,
      mode: state.mode,
      scanIntensity,
      authTier: state.liveHosts ? "Active (attested)" : "Passive (OSINT only)",
      startedAt: state.startedAt,
      endedAt: new Date().toISOString(),
      stagesRun,
      subdomains: state.subdomains,
      liveHosts: state.liveHosts ?? [],
      openPorts: state.openPorts ?? [],
      fingerprints: state.fingerprints ?? [],
      findings: merged,
      riskScore: riskScore(merged),
    };
  }

  // Persist the completed scan (JSON) and fetch its Markdown report for download.
  async function finalizeReport(state: ScanState) {
    try {
      const report = await postJSON<{ markdown: string; savedAs: string | null }>(
        "/api/scan/report",
        { scanResult: buildScanResult(state) },
      );
      setResult({ ...state, report });
    } catch (err) {
      setResult({ ...state, reportError: errMsg(err) });
    }
  }

  function hostPortKey(url: string): string {
    try {
      const u = new URL(url);
      const port = u.port || (u.protocol === "https:" ? "443" : "80");
      return `${u.hostname}:${port}`;
    } catch {
      return url;
    }
  }

  // Active chain: probe -> port scan -> fingerprint -> analysis -> nuclei -> report.
  async function runActiveStages(base: ScanState, toProbe: Subdomain[]) {
    let state = base;

    // Stage 2 — live probe
    setProbing(true);
    let liveHosts: LiveHost[] = [];
    try {
      liveHosts = await postJSON<LiveHost[]>("/api/scan/probe", {
        subdomains: toProbe,
        activeAllowed: true,
        scanIntensity,
      });
      state = { ...state, liveHosts };
      setResult(state);
    } catch (err) {
      setResult({ ...state, probeError: errMsg(err) });
      return;
    } finally {
      setProbing(false);
    }

    if (liveHosts.length === 0) {
      await finalizeReport(state);
      return;
    }

    // Stage 2b — port scan; feed newly-found open web ports back through probe
    setScanningPorts(true);
    try {
      const ports = await postJSON<{
        openPorts: OpenPort[];
        findings: Finding[];
        webTargets: string[];
      }>("/api/scan/ports", { liveHosts, activeAllowed: true, scanIntensity });
      state = { ...state, openPorts: ports.openPorts, portFindings: ports.findings };
      setResult(state);

      const known = new Set(liveHosts.map((h) => hostPortKey(h.url)));
      const newTargets = ports.webTargets.filter((t) => !known.has(t));
      if (newTargets.length > 0) {
        try {
          const extraSubs: Subdomain[] = newTargets.map((t) => ({
            name: t,
            resolves: true,
            records: {},
          }));
          const extra = await postJSON<LiveHost[]>("/api/scan/probe", {
            subdomains: extraSubs,
            activeAllowed: true,
            scanIntensity,
          });
          const seen = new Set(liveHosts.map((h) => h.url));
          for (const h of extra) {
            if (!seen.has(h.url)) {
              liveHosts.push(h);
              seen.add(h.url);
            }
          }
          state = { ...state, liveHosts };
          setResult(state);
        } catch {
          /* re-probing new web ports is best-effort */
        }
      }
    } catch (err) {
      setResult({ ...state, portsError: errMsg(err) });
      // a port-scan failure shouldn't abort the rest of the chain
    } finally {
      setScanningPorts(false);
    }

    // Stage 3 — fingerprint
    setFingerprinting(true);
    let fingerprints: Fingerprint[] = [];
    try {
      fingerprints = await postJSON<Fingerprint[]>("/api/scan/fingerprint", {
        hosts: liveHosts,
        activeAllowed: true,
        scanIntensity,
      });
      state = { ...state, fingerprints };
      setResult(state);
    } catch (err) {
      setResult({ ...state, fingerprintError: errMsg(err) });
      await finalizeReport(state);
      return;
    } finally {
      setFingerprinting(false);
    }

    // Stage 4a — surface analysis
    setAnalyzing(true);
    try {
      const findings = await postJSON<Finding[]>("/api/scan/analysis", {
        liveHosts,
        fingerprints,
        activeAllowed: true,
      });
      state = { ...state, findings };
      setResult(state);
    } catch (err) {
      setResult({ ...state, findingsError: errMsg(err) });
      await finalizeReport(state);
      return;
    } finally {
      setAnalyzing(false);
    }

    // Stage 4b — deep vuln detection with nuclei (NDJSON stream, findings appear live)
    setScanningNuclei(true);
    setNucleiProgress(null);
    const streamed: Finding[] = [];
    try {
      const res = await fetch("/api/scan/nuclei", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          liveHosts,
          activeAllowed: true,
          deepCve,
          scanIntensity,
        }),
      });
      if (!res.ok || !res.body) {
        const data = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(data.error ?? `Request failed (${res.status})`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let status: NucleiResult["status"] = "ok";
      let message: string | undefined;

      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let newline: number;
        while ((newline = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, newline).trim();
          buffer = buffer.slice(newline + 1);
          if (!line) continue;
          let event: NucleiEvent;
          try {
            event = JSON.parse(line) as NucleiEvent;
          } catch {
            continue;
          }
          if (event.type === "finding") {
            streamed.push(event.finding);
            setResult({ ...state, nuclei: { findings: [...streamed], status: "ok" } });
          } else if (event.type === "progress") {
            setNucleiProgress(event.message);
          } else if (event.type === "status") {
            status = event.status;
            message = event.message;
          }
        }
      }
      state = { ...state, nuclei: { findings: streamed, status, message } };
      setResult(state);
    } catch (err) {
      state = { ...state, nucleiError: errMsg(err) };
      setResult(state);
    } finally {
      setScanningNuclei(false);
      setNucleiProgress(null);
    }

    await finalizeReport(state);
  }

  async function runScan() {
    const raw = domain.trim();
    if (!raw || busy) return;

    const { mode, host } = classifyTarget(raw);
    const wantActive = activeScan;
    setError(null);
    setResult(null);
    setNucleiProgress(null);

    console.info(`[aegis] scan started — intensity: ${scanIntensity}`);
    const startedAt = new Date().toISOString();

    const makeState = (subs: Subdomain[]): ScanState => ({
      mode,
      domain: host,
      startedAt,
      subdomains: subs,
      liveHosts: null,
      probeError: null,
      openPorts: null,
      portFindings: [],
      portsError: null,
      fingerprints: null,
      fingerprintError: null,
      findings: null,
      findingsError: null,
      nuclei: null,
      nucleiError: null,
      report: null,
      reportError: null,
    });

    // Direct target: skip discovery, probe + fingerprint the single host.
    if (mode === "direct") {
      const synthetic: Subdomain = { name: host, resolves: true, records: {} };
      const state = makeState([synthetic]);
      setResult(state);
      if (!wantActive) return; // info note prompts enabling Active scan
      await runActiveStages(state, [synthetic]);
      return;
    }

    // Domain: Stage 1 discovery (passive), then active stages if enabled.
    setLoading(true);
    try {
      const subdomains = await postJSON<Subdomain[]>("/api/scan/discovery", {
        domain: host,
      });
      const state = makeState(subdomains);
      setResult(state);
      setLoading(false);
      if (!wantActive) {
        await finalizeReport(state); // persist the passive scan too
        return;
      }
      await runActiveStages(state, subdomains.filter((s) => s.resolves));
    } catch (err) {
      setError(errMsg(err));
      setLoading(false);
    }
  }

  const buttonLabel = loading
    ? "Scanning"
    : probing
      ? "Probing"
      : scanningPorts
        ? "Ports"
        : fingerprinting
          ? "Mapping"
          : analyzing
            ? "Analyzing"
            : scanningNuclei
              ? "Nuclei"
              : "Scan";

  function downloadReport() {
    if (!result?.report) return;
    const blob = new Blob([result.report.markdown], {
      type: "text/markdown;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-report-${result.domain.replace(/[^a-z0-9.-]/gi, "_") || "scan"}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="px-8 py-8">
      <main className="max-w-3xl">
        {/* Heading */}
        <div className="mb-8">
          <h1 className="text-[22px] font-semibold leading-tight tracking-tight text-balance">
            Quick scan
          </h1>
          <p className="mt-1.5 max-w-prose text-sm leading-relaxed text-text-dim text-pretty">
            One-off scan of a single target: discover hosts, probe what&apos;s live,
            fingerprint the stack, triage exposures, and download the report.
          </p>
        </div>

        {/* Command bar — the focal point */}
        <section className="rounded-xl border border-border bg-surface p-5">
          <label
            htmlFor="target"
            className="mb-2 block font-mono text-[11px] uppercase tracking-[0.18em] text-text-faint"
          >
            Target
          </label>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              runScan();
            }}
            className="flex flex-col gap-3 sm:flex-row"
          >
            <div className="relative flex-1">
              <TargetGlyph className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-faint" />
              <input
                id="target"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com or localhost:3000"
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                className="h-11 w-full rounded-lg border border-border bg-control pl-9 pr-3 font-mono text-sm text-text outline-none transition-colors placeholder:text-text-faint focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent-ring"
              />
            </div>
            <button
              type="submit"
              disabled={!canScan || busy}
              className="flex h-11 shrink-0 items-center justify-center rounded-lg bg-accent px-6 text-sm font-semibold text-accent-contrast outline-none transition-[background-color,transform] hover:bg-accent-hover focus-visible:ring-2 focus-visible:ring-accent-ring active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-accent sm:w-32"
            >
              {busy ? (
                <span className="flex items-center gap-2">
                  <Spinner className="h-4 w-4" />
                  {buttonLabel}
                </span>
              ) : (
                "Scan"
              )}
            </button>
          </form>

          {canScan && (
            <p className="mt-2.5 text-[12px] leading-relaxed text-text-faint">
              {liveClass.mode === "direct" ? (
                <>
                  <span className="text-accent">Direct target</span> — probes{" "}
                  <span className="font-mono text-text-dim">
                    {liveClass.host}
                  </span>{" "}
                  directly, skipping discovery
                  {!activeScan && " · needs Active scan"}
                </>
              ) : (
                <>
                  <span className="text-text-dim">Domain</span> — enumerates
                  subdomains of{" "}
                  <span className="font-mono text-text-dim">
                    {liveClass.host}
                  </span>
                </>
              )}
            </p>
          )}

          {/* Active-scan control — the signature */}
          <div className="mt-5 border-t border-border-soft pt-4">
            <div className="mb-4 flex items-center justify-between gap-4">
              <div className="min-w-0">
                <span className="text-sm font-medium">Scan intensity</span>
                <p className="mt-1 text-[13px] leading-relaxed text-text-dim">
                  How hard active stages hit the target — polite is slow and kind,
                  aggressive is fast.
                </p>
              </div>
              <select
                value={scanIntensity}
                onChange={(e) =>
                  setScanIntensity(e.target.value as ScanIntensity)
                }
                className="h-9 shrink-0 rounded-lg border border-border bg-control px-3 font-mono text-[13px] text-text outline-none transition-colors focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent-ring"
              >
                {(["polite", "normal", "aggressive"] as ScanIntensity[]).map(
                  (key) => (
                    <option key={key} value={key}>
                      {INTENSITY_PROFILES[key].label}
                    </option>
                  ),
                )}
              </select>
            </div>

            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">Active scan</span>
                  <span
                    className={`font-mono text-[10px] uppercase tracking-wider ${
                      activeScan ? "text-caution" : "text-text-faint"
                    }`}
                  >
                    {activeScan ? "armed" : "passive"}
                  </span>
                </div>
                <p className="mt-1 text-[13px] leading-relaxed text-text-dim">
                  {activeScan
                    ? "Probes resolved hosts and fingerprints their stack with live requests."
                    : "Passive only — OSINT and DNS. No packets are sent to the target."}
                </p>
              </div>
              <Switch
                checked={activeScan}
                onChange={setActiveScan}
                label="Active scan"
              />
            </div>

            {activeScan && (
              <div className="mt-3 flex gap-2.5 rounded-lg border border-caution-border bg-caution-bg px-3.5 py-2.5">
                <WarnGlyph className="mt-0.5 h-4 w-4 shrink-0 text-caution" />
                <p className="text-[13px] leading-relaxed text-text-dim">
                  <span className="font-medium text-caution">
                    Authorization required.
                  </span>{" "}
                  Active scanning may be unlawful without permission. Only enable
                  it for assets you own or are explicitly authorized to test.
                </p>
              </div>
            )}

            {activeScan && (
              <div className="mt-3 flex items-start justify-between gap-4 border-t border-border-soft pt-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">Deep CVE scan</span>
                    <span className="font-mono text-[10px] uppercase tracking-wider text-text-faint">
                      nuclei · cve
                    </span>
                  </div>
                  <p className="mt-1 text-[13px] leading-relaxed text-text-dim">
                    Adds nuclei&apos;s full CVE template set (~4k more templates).
                    Much slower, and its exploit payloads can crash fragile
                    single-host targets (e.g. Juice Shop).
                  </p>
                </div>
                <Switch
                  checked={deepCve}
                  onChange={setDeepCve}
                  label="Deep CVE scan"
                />
              </div>
            )}
          </div>
        </section>

        {/* Results */}
        <section className="mt-6">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h2 className="font-mono text-[11px] uppercase tracking-[0.18em] text-text-faint">
              Results
            </h2>
            <div className="flex items-center gap-2">
              {result?.report && (
                <button
                  type="button"
                  onClick={downloadReport}
                  className="flex items-center gap-1.5 rounded-lg border border-border bg-surface-raised px-3 py-1.5 text-[12px] font-medium text-text-dim outline-none transition-colors hover:border-accent hover:text-text focus-visible:ring-2 focus-visible:ring-accent-ring"
                >
                  <DownloadGlyph className="h-3.5 w-3.5" />
                  Download report
                </button>
              )}
              {result && <ModeBadge mode={result.mode} />}
            </div>
          </div>

          {loading ? (
            <ResultPanel>
              <Spinner className="h-6 w-6 text-accent" />
              <p className="mt-4 text-sm font-medium text-text-dim">
                Scanning {domain.trim()}…
              </p>
              <p className="mt-1 max-w-xs text-[13px] leading-relaxed text-text-faint">
                Querying certificate transparency logs and resolving DNS. Passive —
                no requests are sent to the target.
              </p>
            </ResultPanel>
          ) : error ? (
            <ErrorBanner title="Scan failed" message={error} />
          ) : result ? (
            <div className="space-y-8">
              {result.mode === "domain" && (
                <div>
                  <StageHeading
                    label="Discovery"
                    stage="Stage 1 · Passive"
                    tone="live"
                  />
                  <DiscoveryResults result={result} />
                </div>
              )}

              {result.mode === "direct" && !activeScan && (
                <InfoBanner
                  title="Direct target mode"
                  message={`Probing and fingerprinting a single host is an active operation. Enable Active scan and run again to inspect ${result.domain}.`}
                />
              )}

              {activeScan && (
                <div>
                  <StageHeading
                    label="Live hosts"
                    stage="Stage 2 · Active"
                    tone="caution"
                  />
                  <LiveHostsBody result={result} probing={probing} />
                </div>
              )}

              {activeScan &&
                (scanningPorts || result.openPorts || result.portsError) && (
                  <div>
                    <StageHeading
                      label="Open ports"
                      stage="Stage 2b · Active"
                      tone="caution"
                    />
                    <PortsBody result={result} scanningPorts={scanningPorts} />
                  </div>
                )}

              {activeScan &&
                (fingerprinting ||
                  result.fingerprints ||
                  result.fingerprintError) && (
                  <div>
                    <StageHeading
                      label="Fingerprint"
                      stage="Stage 3 · Active"
                      tone="caution"
                    />
                    <FingerprintBody
                      result={result}
                      fingerprinting={fingerprinting}
                    />
                  </div>
                )}

              {activeScan &&
                (analyzing ||
                  scanningNuclei ||
                  result.findings ||
                  result.findingsError) && (
                  <div>
                    <StageHeading
                      label="Findings & risk"
                      stage="Stage 4 · Analysis + nuclei"
                      tone="caution"
                    />
                    <FindingsBody
                      result={result}
                      analyzing={analyzing}
                      scanningNuclei={scanningNuclei}
                      nucleiProgress={nucleiProgress}
                    />
                  </div>
                )}
            </div>
          ) : (
            <ResultPanel dashed>
              <ScanGlyph className="h-7 w-7 text-text-faint" />
              <p className="mt-4 text-sm font-medium text-text-dim">No scan yet</p>
              <p className="mt-1 max-w-xs text-[13px] leading-relaxed text-text-faint">
                Enter a target domain and run a scan to map its attack surface.
                Findings appear here, ordered by severity.
              </p>
            </ResultPanel>
          )}
        </section>
      </main>
    </div>
  );
}

function DiscoveryResults({ result }: { result: ScanState }) {
  const { domain, subdomains } = result;
  const total = subdomains.length;
  const resolvedCount = subdomains.filter((s) => s.resolves).length;

  if (total === 0) {
    return (
      <ResultPanel dashed>
        <ScanGlyph className="h-7 w-7 text-text-faint" />
        <p className="mt-4 text-sm font-medium text-text-dim">
          No subdomains found
        </p>
        <p className="mt-1 max-w-xs text-[13px] leading-relaxed text-text-faint">
          Certificate transparency returned no names for{" "}
          <span className="font-mono text-text-dim">{domain}</span>.
        </p>
      </ResultPanel>
    );
  }

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <p className="flex items-baseline gap-2">
          <span className="font-mono text-2xl font-semibold tabular-nums text-text">
            {total.toLocaleString()}
          </span>
          <span className="text-sm text-text-dim">
            subdomains found for{" "}
            <span className="font-mono text-text">{domain}</span>
          </span>
        </p>
        <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-signal-live">
          {resolvedCount.toLocaleString()} resolved
        </span>
      </div>

      {total > DNS_RESOLVE_CAP && (
        <p className="mb-3 text-[12px] leading-relaxed text-text-faint">
          DNS resolution capped at {DNS_RESOLVE_CAP} for responsiveness; the
          remaining {(total - DNS_RESOLVE_CAP).toLocaleString()} are listed
          without records.
        </p>
      )}

      <div className="max-h-[60vh] overflow-auto rounded-xl border border-border bg-surface">
        <table className="w-full border-collapse text-[13px]">
          <thead className="sticky top-0 z-10 bg-surface">
            <tr className="border-b border-border">
              <th className="w-8 px-3 py-2.5" aria-label="Resolves" />
              <Th>Subdomain</Th>
              <Th>A</Th>
              <Th>CNAME</Th>
              <Th>MX</Th>
              <Th>TXT</Th>
            </tr>
          </thead>
          <tbody>
            {subdomains.map((s) => (
              <tr
                key={s.name}
                className="border-b border-border-soft align-top transition-colors last:border-0 hover:bg-white/[0.02]"
              >
                <td className="px-3 py-2.5">
                  <Dot resolves={s.resolves} />
                </td>
                <td className="px-3 py-2.5 font-mono text-text break-all">
                  {s.name}
                </td>
                <td className="whitespace-nowrap px-3 py-2.5 font-mono text-text-dim">
                  <RecordList values={s.records.A} />
                </td>
                <td className="px-3 py-2.5 font-mono text-text-dim break-all">
                  <RecordList values={s.records.CNAME} />
                </td>
                <td className="whitespace-nowrap px-3 py-2.5 font-mono text-text-dim">
                  <RecordList values={s.records.MX} />
                </td>
                <td className="max-w-[360px] px-3 py-2.5 font-mono text-[12px] text-text-dim break-all">
                  <RecordList values={s.records.TXT} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function LiveHostsBody({
  result,
  probing,
}: {
  result: ScanState;
  probing: boolean;
}) {
  if (probing) {
    return (
      <StageLoading
        title="Probing live hosts…"
        detail="Sending HTTP/HTTPS requests to resolved hosts (5s timeout, 10 at a time)."
      />
    );
  }
  if (result.probeError) {
    return <ErrorBanner title="Probe failed" message={result.probeError} />;
  }

  const hosts = result.liveHosts;
  if (hosts === null) return <EmptyNote>Re-run the scan to probe live hosts.</EmptyNote>;
  if (hosts.length === 0) return <EmptyNote>No live hosts responded.</EmptyNote>;

  return (
    <div>
      <p className="mb-3 flex items-baseline gap-2">
        <span className="font-mono text-2xl font-semibold tabular-nums text-text">
          {hosts.length.toLocaleString()}
        </span>
        <span className="text-sm text-text-dim">
          live {hosts.length === 1 ? "host" : "hosts"} responding
        </span>
      </p>

      <div className="max-h-[60vh] overflow-auto rounded-xl border border-border bg-surface">
        <table className="w-full border-collapse text-[13px]">
          <thead className="sticky top-0 z-10 bg-surface">
            <tr className="border-b border-border">
              <Th>Status</Th>
              <Th>Host</Th>
              <Th>Title</Th>
              <Th>Server</Th>
              <Th>X-Powered-By</Th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h, i) => (
              <tr
                key={`${h.url}-${i}`}
                className="border-b border-border-soft align-top transition-colors last:border-0 hover:bg-white/[0.02]"
              >
                <td className="px-3 py-2.5">
                  <StatusBadge status={h.status} />
                </td>
                <td className="px-3 py-2.5 font-mono text-text break-all">
                  {h.url}
                  <span className="mt-0.5 block text-[11px] text-text-faint">
                    {h.responseTimeMs}ms
                    {h.contentLength != null
                      ? ` · ${h.contentLength.toLocaleString()} B`
                      : ""}
                    {h.ip ? ` · ${h.ip}` : ""}
                  </span>
                </td>
                <td className="px-3 py-2.5 text-text-dim break-all">
                  {h.title || <span className="text-text-faint">—</span>}
                </td>
                <td className="px-3 py-2.5 font-mono text-text-dim break-all">
                  {h.server || <span className="text-text-faint">—</span>}
                </td>
                <td className="px-3 py-2.5 font-mono text-text-dim break-all">
                  {h.xPoweredBy || <span className="text-text-faint">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function FingerprintBody({
  result,
  fingerprinting,
}: {
  result: ScanState;
  fingerprinting: boolean;
}) {
  if (fingerprinting) {
    return (
      <StageLoading
        title="Fingerprinting live hosts…"
        detail="Detecting technologies, inspecting JS bundles, and probing exposed paths."
      />
    );
  }
  if (result.fingerprintError) {
    return <ErrorBanner title="Fingerprint failed" message={result.fingerprintError} />;
  }

  const fps = result.fingerprints;
  if (!fps || fps.length === 0) return null;

  return (
    <div className="space-y-3">
      {fps.map((fp, i) => (
        <FingerprintCard key={`${fp.host}-${i}`} fp={fp} />
      ))}
    </div>
  );
}

function FingerprintCard({ fp }: { fp: Fingerprint }) {
  return (
    <div className="rounded-xl border border-border bg-surface p-4">
      <p className="font-mono text-[13px] text-text break-all">{fp.host}</p>

      <div className="mt-3">
        <span className="font-mono text-[10px] uppercase tracking-wider text-text-faint">
          Technologies
        </span>
        {fp.technologies.length > 0 ? (
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {fp.technologies.map((t, i) => (
              <span
                key={i}
                className="rounded-md border border-border bg-surface-raised px-2 py-0.5 font-mono text-[11px] text-text-dim"
              >
                {t.name}
                {t.version ? (
                  <span className="text-text-faint"> {t.version}</span>
                ) : null}
              </span>
            ))}
          </div>
        ) : (
          <p className="mt-1 text-[13px] text-text-faint">
            No technologies detected.
          </p>
        )}
      </div>

      {fp.exposedPaths.length > 0 && (
        <div className="mt-3">
          <span className="font-mono text-[10px] uppercase tracking-wider text-text-faint">
            Exposed paths
          </span>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {fp.exposedPaths.map((p, i) => {
              const high = /^\/\.(git|env)/.test(p);
              const cls = high
                ? "border-signal-critical/40 bg-signal-critical/[0.08] text-signal-critical"
                : "border-caution-border bg-caution-bg text-caution";
              return (
                <span
                  key={i}
                  className={`rounded-md border px-2 py-0.5 font-mono text-[11px] ${cls}`}
                >
                  {p}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {fp.links.length > 0 && (
        <p className="mt-3 font-mono text-[11px] text-text-faint">
          {fp.links.length} internal link{fp.links.length === 1 ? "" : "s"} crawled
        </p>
      )}
    </div>
  );
}

const SEVERITY_CLASS: Record<Severity, string> = {
  CRITICAL:
    "border-signal-critical/50 bg-signal-critical/[0.14] text-signal-critical",
  HIGH: "border-signal-critical/40 bg-signal-critical/[0.08] text-signal-critical",
  MEDIUM: "border-caution-border bg-caution-bg text-caution",
  LOW: "border-border bg-surface-raised text-text-dim",
  INFO: "border-border bg-surface-raised text-text-faint",
};

const SEVERITY_SORT: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function FindingsBody({
  result,
  analyzing,
  scanningNuclei,
  nucleiProgress,
}: {
  result: ScanState;
  analyzing: boolean;
  scanningNuclei: boolean;
  nucleiProgress: string | null;
}) {
  if (analyzing) {
    return (
      <StageLoading
        title="Analyzing surface…"
        detail="Checking security headers, TLS certificates, exposed paths, and component versions."
      />
    );
  }
  if (result.findingsError) {
    return <ErrorBanner title="Analysis failed" message={result.findingsError} />;
  }
  if (!result.findings) return null;

  // Merge analysis + nuclei + port findings, deduped and severity-sorted.
  const merged = sortFindings(
    dedupeFindings([
      ...result.findings,
      ...(result.nuclei?.findings ?? []),
      ...result.portFindings,
    ]),
  );
  const hosts = result.liveHosts ?? [];

  return (
    <div>
      <RiskHeadline findings={merged} hostCount={hosts.length} />

      {scanningNuclei && (
        <div className="mb-3 flex items-center gap-2.5 rounded-lg border border-border bg-surface px-3.5 py-2.5">
          <Spinner className="h-4 w-4 text-accent" />
          <p className="text-[13px] leading-relaxed text-text-dim">
            Running <span className="font-mono">nuclei</span> deep vulnerability
            scan — findings stream in as they&apos;re found.{" "}
            <span className="text-text-faint">
              {nucleiProgress ?? "Starting up… the first run downloads templates."}
            </span>
          </p>
        </div>
      )}

      {!scanningNuclei &&
        result.nuclei &&
        result.nuclei.status !== "ok" && (
          <p className="mb-3 rounded-lg border border-caution-border bg-caution-bg px-3.5 py-2.5 text-[13px] leading-relaxed text-text-dim">
            <span className="font-medium text-caution">
              {result.nuclei.status === "partial"
                ? "Deep scan incomplete."
                : "nuclei skipped."}
            </span>{" "}
            {result.nuclei.message ?? "Showing header/path findings only."}
          </p>
        )}

      {!scanningNuclei && result.nucleiError && (
        <p className="mb-3 rounded-lg border border-caution-border bg-caution-bg px-3.5 py-2.5 text-[13px] leading-relaxed text-text-dim">
          <span className="font-medium text-caution">nuclei error.</span>{" "}
          {result.nucleiError} Showing header/path findings only.
        </p>
      )}

      {merged.length === 0 ? (
        <EmptyNote>No findings — nothing notable surfaced.</EmptyNote>
      ) : (
        <div className="max-h-[60vh] overflow-auto rounded-xl border border-border bg-surface">
          <table className="w-full border-collapse text-[13px]">
            <thead className="sticky top-0 z-10 bg-surface">
              <tr className="border-b border-border">
                <Th>Severity</Th>
                <Th>Finding</Th>
                <Th>Host</Th>
              </tr>
            </thead>
            <tbody>
              {merged.map((f, i) => (
                <tr
                  key={i}
                  className="border-b border-border-soft align-top transition-colors last:border-0 hover:bg-white/[0.02]"
                >
                  <td className="px-3 py-2.5">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-3 py-2.5">
                    <p className="font-medium text-text">{f.title}</p>
                    <p className="mt-0.5 leading-relaxed text-text-dim">
                      {f.description}
                    </p>
                    <p className="mt-1 text-[12px] leading-relaxed text-text-faint">
                      <span className="text-signal-live">Fix:</span>{" "}
                      {f.recommendation}
                    </p>
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[12px] text-text-dim break-all">
                    {f.host}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function RiskHeadline({
  findings,
  hostCount,
}: {
  findings: Finding[];
  hostCount: number;
}) {
  const score = riskScore(findings);
  const level = riskLevel(findings);
  const counts = severityCounts(findings);
  const byHost = riskScoreByHost(findings);

  const scoreTone =
    level.tone === "critical" || level.tone === "high"
      ? "text-signal-critical"
      : level.tone === "elevated"
        ? "text-caution"
        : level.tone === "low"
          ? "text-text-dim"
          : "text-signal-live";
  const badgeTone =
    level.tone === "critical" || level.tone === "high"
      ? "border-signal-critical/40 bg-signal-critical/[0.1] text-signal-critical"
      : level.tone === "elevated"
        ? "border-caution-border bg-caution-bg text-caution"
        : level.tone === "low"
          ? "border-border bg-surface-raised text-text-dim"
          : "border-signal-live/30 bg-signal-live/[0.08] text-signal-live";

  return (
    <div className="mb-4 rounded-xl border border-border bg-surface p-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-text-faint">
            Risk score
          </span>
          <div className="mt-1 flex items-baseline gap-2.5">
            <span
              className={`font-mono text-4xl font-semibold tabular-nums ${scoreTone}`}
            >
              {score}
            </span>
            <span
              className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${badgeTone}`}
            >
              {level.label}
            </span>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {SEVERITY_SORT.filter((s) => counts[s] > 0).map((s) => (
            <span
              key={s}
              className={`rounded-md border px-2 py-0.5 font-mono text-[11px] tabular-nums ${SEVERITY_CLASS[s]}`}
            >
              {counts[s]} {s}
            </span>
          ))}
        </div>
      </div>

      {hostCount > 1 && Object.keys(byHost).length > 0 && (
        <div className="mt-4 border-t border-border-soft pt-3">
          <span className="font-mono text-[10px] uppercase tracking-wider text-text-faint">
            Per host
          </span>
          <div className="mt-1.5 space-y-1">
            {Object.entries(byHost)
              .sort((a, b) => b[1] - a[1])
              .map(([host, s]) => (
                <div
                  key={host}
                  className="flex items-center justify-between gap-3 text-[12px]"
                >
                  <span className="font-mono text-text-dim break-all">{host}</span>
                  <span className="font-mono tabular-nums text-text">{s}</span>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

function PortsBody({
  result,
  scanningPorts,
}: {
  result: ScanState;
  scanningPorts: boolean;
}) {
  if (scanningPorts) {
    return (
      <StageLoading
        title="Scanning ports…"
        detail="TCP-connect scan over ~90 common ports per host, paced by the intensity setting."
      />
    );
  }
  if (result.portsError) {
    return <ErrorBanner title="Port scan failed" message={result.portsError} />;
  }

  const ports = result.openPorts;
  if (!ports) return null;
  if (ports.length === 0) {
    return <EmptyNote>No open ports found on the scanned hosts.</EmptyNote>;
  }

  const severityByHostPort = new Map(
    result.portFindings.map((f) => [f.host, f.severity]),
  );

  return (
    <div>
      <p className="mb-3 flex items-baseline gap-2">
        <span className="font-mono text-2xl font-semibold tabular-nums text-text">
          {ports.length}
        </span>
        <span className="text-sm text-text-dim">
          open {ports.length === 1 ? "port" : "ports"}
        </span>
      </p>

      <div className="max-h-[50vh] overflow-auto rounded-xl border border-border bg-surface">
        <table className="w-full border-collapse text-[13px]">
          <thead className="sticky top-0 z-10 bg-surface">
            <tr className="border-b border-border">
              <th className="w-8 px-3 py-2.5" aria-label="Risk" />
              <Th>Port</Th>
              <Th>Service</Th>
              <Th>Host</Th>
            </tr>
          </thead>
          <tbody>
            {ports.map((p, i) => {
              const risky =
                severityByHostPort.get(`${p.host}:${p.port}`) === "HIGH";
              return (
                <tr
                  key={`${p.host}-${p.port}-${i}`}
                  className="border-b border-border-soft transition-colors last:border-0 hover:bg-white/[0.02]"
                >
                  <td className="px-3 py-2.5">
                    <span
                      title={risky ? "Risky exposed service" : "Open"}
                      className={`inline-block h-2 w-2 rounded-full ${
                        risky ? "bg-signal-critical" : "bg-text-faint/40"
                      }`}
                    />
                  </td>
                  <td className="px-3 py-2.5 font-mono tabular-nums text-text">
                    {p.port}
                  </td>
                  <td
                    className={`px-3 py-2.5 ${risky ? "font-medium text-signal-critical" : "text-text-dim"}`}
                  >
                    {p.service}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[12px] text-text-dim break-all">
                    {p.host}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wider ${SEVERITY_CLASS[severity]}`}
    >
      {severity}
    </span>
  );
}

function StageHeading({
  label,
  stage,
  tone,
}: {
  label: string;
  stage: string;
  tone: "live" | "caution";
}) {
  const toneCls =
    tone === "caution"
      ? "border-caution-border bg-caution-bg text-caution"
      : "border-signal-live/30 bg-signal-live/[0.08] text-signal-live";
  return (
    <div className="mb-3 flex items-center justify-between">
      <h3 className="text-sm font-semibold text-text">{label}</h3>
      <span
        className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${toneCls}`}
      >
        {stage}
      </span>
    </div>
  );
}

function StageLoading({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-border bg-surface px-5 py-6">
      <Spinner className="h-5 w-5 text-accent" />
      <div>
        <p className="text-sm font-medium text-text-dim">{title}</p>
        <p className="mt-0.5 text-[13px] leading-relaxed text-text-faint">
          {detail}
        </p>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: number }) {
  const cls =
    status >= 500
      ? "border-signal-critical/40 bg-signal-critical/[0.08] text-signal-critical"
      : status >= 400
        ? "border-caution-border bg-caution-bg text-caution"
        : status >= 300
          ? "border-accent/30 bg-accent/[0.08] text-accent"
          : "border-signal-live/30 bg-signal-live/[0.08] text-signal-live";
  return (
    <span
      className={`inline-block rounded-md border px-1.5 py-0.5 font-mono text-[11px] tabular-nums ${cls}`}
    >
      {status}
    </span>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-3 py-2.5 text-left font-mono text-[11px] font-medium uppercase tracking-[0.14em] text-text-faint">
      {children}
    </th>
  );
}

function RecordList({ values }: { values?: string[] }) {
  if (!values || values.length === 0) {
    return <span className="text-text-faint">—</span>;
  }
  return (
    <ul className="space-y-0.5">
      {values.map((v, i) => (
        <li key={i}>{v}</li>
      ))}
    </ul>
  );
}

function Dot({ resolves }: { resolves: boolean }) {
  return (
    <span
      title={resolves ? "Resolves" : "No DNS records"}
      className={`inline-block h-2 w-2 rounded-full ${
        resolves ? "bg-signal-live" : "bg-text-faint/40"
      }`}
    />
  );
}

function EmptyNote({ children }: { children: React.ReactNode }) {
  return (
    <p className="rounded-xl border border-dashed border-border px-5 py-6 text-[13px] text-text-faint">
      {children}
    </p>
  );
}

function ErrorBanner({ title, message }: { title: string; message: string }) {
  return (
    <div className="flex items-start gap-2.5 rounded-xl border border-signal-critical/40 bg-signal-critical/[0.08] px-4 py-3.5">
      <WarnGlyph className="mt-0.5 h-4 w-4 shrink-0 text-signal-critical" />
      <div>
        <p className="text-sm font-medium text-text">{title}</p>
        <p className="mt-0.5 text-[13px] leading-relaxed text-text-dim">
          {message}
        </p>
      </div>
    </div>
  );
}

function InfoBanner({ title, message }: { title: string; message: string }) {
  return (
    <div className="flex items-start gap-2.5 rounded-xl border border-border bg-surface px-4 py-3.5">
      <InfoGlyph className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
      <div>
        <p className="text-sm font-medium text-text">{title}</p>
        <p className="mt-0.5 text-[13px] leading-relaxed text-text-dim">
          {message}
        </p>
      </div>
    </div>
  );
}

function ModeBadge({ mode }: { mode: TargetMode }) {
  if (mode === "direct") {
    return (
      <span className="rounded-full border border-accent/30 bg-accent/[0.08] px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-accent">
        Direct target
      </span>
    );
  }
  return (
    <span className="rounded-full border border-border bg-surface-raised px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-dim">
      Domain enumeration
    </span>
  );
}

function ResultPanel({
  children,
  dashed = false,
}: {
  children: React.ReactNode;
  dashed?: boolean;
}) {
  return (
    <div
      className={`flex min-h-[260px] flex-col items-center justify-center rounded-xl border px-6 py-14 text-center ${
        dashed ? "border-dashed border-border" : "border-border bg-surface"
      }`}
    >
      {children}
    </div>
  );
}

/** Accessible on/off switch (native button + role="switch"). */
function Switch({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border outline-none transition-colors focus-visible:ring-2 focus-visible:ring-accent-ring ${
        checked ? "border-accent bg-accent/25" : "border-border bg-surface-raised"
      }`}
    >
      <span
        className={`inline-block h-4 w-4 rounded-full transition-transform ${
          checked ? "translate-x-5 bg-accent" : "translate-x-1 bg-text-faint"
        }`}
      />
    </button>
  );
}

function Spinner({ className }: { className?: string }) {
  return (
    <svg
      className={`animate-spin ${className ?? ""}`}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle
        cx="12"
        cy="12"
        r="9"
        stroke="currentColor"
        strokeWidth="2.5"
        className="opacity-20"
      />
      <path
        d="M21 12a9 9 0 0 0-9-9"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

function TargetGlyph({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="7" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
      <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
    </svg>
  );
}

function WarnGlyph({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M10.3 3.9 1.9 18a2 2 0 0 0 1.7 3h16.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9v4M12 17h.01" />
    </svg>
  );
}

function InfoGlyph({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </svg>
  );
}

function ScanGlyph({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
      <path d="M3 12h18" />
    </svg>
  );
}

function DownloadGlyph({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M12 3v12M7 11l5 4 5-4M5 21h14" />
    </svg>
  );
}
