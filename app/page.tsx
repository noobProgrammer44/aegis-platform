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

export default function Home() {
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

  // Pipeline state for the stage rail. Stage 1 is passive; 2–5 sit behind the
  // authorization line and stay locked until Active scan is armed.
  const mode: TargetMode = result?.mode ?? (canScan ? liveClass.mode : "domain");
  const stages: Stage[] = [
    {
      name: "Discover",
      state:
        mode === "direct"
          ? "skipped"
          : loading
            ? "running"
            : error
              ? "error"
              : result
                ? "done"
                : "idle",
    },
    {
      name: "Probe",
      state: !activeScan
        ? "locked"
        : probing
          ? "running"
          : result?.probeError
            ? "error"
            : result?.liveHosts
              ? "done"
              : "idle",
    },
    {
      name: "Ports",
      state: !activeScan
        ? "locked"
        : scanningPorts
          ? "running"
          : result?.portsError
            ? "error"
            : result?.openPorts
              ? "done"
              : "idle",
    },
    {
      name: "Fingerprint",
      state: !activeScan
        ? "locked"
        : fingerprinting
          ? "running"
          : result?.fingerprintError
            ? "error"
            : result?.fingerprints
              ? "done"
              : "idle",
    },
    {
      name: "Analyze",
      state: !activeScan
        ? "locked"
        : analyzing || scanningNuclei
          ? "running"
          : result?.findingsError
            ? "error"
            : result?.findings
              ? "done"
              : "idle",
    },
  ];

  const showFindings =
    activeScan &&
    result !== null &&
    (analyzing || scanningNuclei || result.findings !== null || result.findingsError !== null);

  const phase: Phase = busy ? "scanning" : result ? "done" : "idle";
  const allFindings = result?.findings
    ? mergedFindings(result)
    : null;
  const blips = radarBlips(result, allFindings);
  const reachable = stages.filter((s) => s.state !== "locked");
  const progress = reachable.length
    ? reachable.filter((s) => s.state === "done" || s.state === "skipped").length /
      reachable.length
    : 0;
  const worst = allFindings?.length ? sortFindings(allFindings)[0].severity : null;
  const stats: RadarStat[] = [
    { label: "Found", value: result ? result.subdomains.length : null, tone: "text-text" },
    {
      label: "Resolve",
      value: result ? result.subdomains.filter((s) => s.resolves).length : null,
      tone: "text-accent",
    },
    { label: "Live", value: result?.liveHosts?.length ?? null, tone: "text-signal-live" },
    { label: "Ports", value: result?.openPorts?.length ?? null, tone: "text-accent-2" },
    {
      label: "Findings",
      value: allFindings?.length ?? null,
      tone: worst ? SEVERITY_TEXT[worst] : "text-text",
    },
  ];

  return (
    <div className="relative min-h-screen text-text">
      <header className="relative z-10 border-b border-border-soft bg-canvas/50 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-3 px-6">
          <div className="flex items-center gap-2.5">
            <ShieldMark className="h-5 w-5 text-accent drop-shadow-[0_0_8px_rgba(34,211,238,0.55)]" />
            <Label>Attack surface scanner</Label>
          </div>
          <StatusPill phase={phase} armed={activeScan} />
        </div>
      </header>

      <main className="relative z-10 mx-auto max-w-6xl px-6 pb-24 pt-12">
        <div className="grid items-center gap-12 lg:grid-cols-[minmax(0,1fr)_380px] lg:gap-16">
          <div className="min-w-0">
            <div className="mb-8">
              <h1 className="w-fit bg-[linear-gradient(100deg,var(--text)_35%,var(--accent)_80%,var(--accent-2))] bg-clip-text pb-1 text-[48px] font-semibold leading-none tracking-[-0.04em] text-transparent">
                Aegis
              </h1>
              <p className="mt-3 max-w-prose text-[15px] leading-relaxed text-text-dim text-pretty">
                Map a domain&apos;s externally reachable surface: discover hosts,
                probe what&apos;s live, fingerprint the stack, and triage exposures.
              </p>
            </div>

            {/* Command bar: the focal point. Its edge turns amber when armed. */}
            <section
              className={`rounded-2xl p-px transition-shadow duration-300 ${
                activeScan
                  ? "bg-[linear-gradient(140deg,rgba(245,158,11,0.6),rgba(245,158,11,0.1)_45%,rgba(148,197,255,0.08))] shadow-[0_24px_64px_-40px_rgba(245,158,11,0.5)]"
                  : "bg-[linear-gradient(140deg,rgba(34,211,238,0.55),rgba(56,189,248,0.12)_45%,rgba(148,197,255,0.08))] shadow-[0_24px_64px_-40px_rgba(34,211,238,0.55)]"
              }`}
            >
              <div className="rounded-[15px] bg-surface/95 p-5 backdrop-blur-sm">
                <label htmlFor="target" className="mb-2 block">
                  <Label>Target</Label>
                </label>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    runScan();
                  }}
                  className="flex flex-col gap-3 sm:flex-row"
                >
                  <div className="relative flex-1">
                    <TargetGlyph className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-accent/70" />
                    <input
                      id="target"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      placeholder="example.com or localhost:3000"
                      autoComplete="off"
                      autoCapitalize="off"
                      spellCheck={false}
                      className="h-11 w-full rounded-lg border border-border bg-control pl-9 pr-3 font-mono text-sm text-text outline-none transition-[border-color,box-shadow] duration-150 placeholder:text-text-faint focus-visible:border-accent/70 focus-visible:shadow-[0_0_0_3px_var(--accent-ring),0_0_24px_-4px_rgba(34,211,238,0.45)]"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={!canScan || busy}
                    aria-busy={busy}
                    className={`flex h-11 shrink-0 items-center justify-center rounded-lg px-6 text-sm font-semibold outline-none transition-[filter,transform,box-shadow] duration-150 focus-visible:ring-2 focus-visible:ring-accent-ring sm:w-32 ${
                      !canScan
                        ? "cursor-not-allowed bg-surface-raised text-text-faint"
                        : busy
                          ? "anim-shimmer cursor-progress bg-[linear-gradient(90deg,var(--accent),var(--accent-2),var(--accent))] text-accent-contrast"
                          : "bg-[linear-gradient(135deg,var(--accent),var(--accent-2))] text-accent-contrast shadow-[0_8px_28px_-8px_rgba(34,211,238,0.7)] hover:brightness-110 active:scale-[0.97]"
                    }`}
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
                        <span className="text-text-dim">Direct target</span> — probes{" "}
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

                {/* Arm control + stage rail: the signature */}
                <div className="mt-4 border-t border-border-soft pt-2">
                  <SwitchRow
                    id="arm"
                    checked={activeScan}
                    onChange={setActiveScan}
                    title="Active scan"
                    tag={
                      <Label className={activeScan ? "text-caution" : "text-text-faint"}>
                        {activeScan ? "Armed" : "Passive"}
                      </Label>
                    }
                    description={
                      activeScan
                        ? "Probes resolved hosts, scans common ports, and fingerprints their stack with live requests."
                        : "Passive only — OSINT and DNS. No packets are sent to the target."
                    }
                  />

                  {activeScan && (
                    <div className="anim-rise mt-1 flex gap-2.5 rounded-lg border border-caution-border bg-caution-bg px-3.5 py-2.5">
                      <WarnGlyph className="mt-0.5 h-4 w-4 shrink-0 text-caution" />
                      <p className="text-[13px] leading-relaxed text-text-dim">
                        <span className="font-medium text-caution">
                          Authorization required.
                        </span>{" "}
                        Active scanning may be unlawful without permission. Only
                        enable it for assets you own or are explicitly authorized
                        to test.
                      </p>
                    </div>
                  )}

                  {activeScan && (
                    <div className="anim-rise mt-3 divide-y divide-border-soft border-t border-border-soft">
                      <IntensityControl
                        value={scanIntensity}
                        onChange={setScanIntensity}
                      />
                      <SwitchRow
                        id="deep-cve"
                        checked={deepCve}
                        onChange={setDeepCve}
                        title="Deep CVE scan"
                        tag={<Label>nuclei · cve</Label>}
                        description="Adds nuclei's full CVE template set (~4k more templates). Much slower, and its exploit payloads can crash fragile single-host targets (e.g. Juice Shop)."
                      />
                    </div>
                  )}

                  <StageRail
                    stages={stages}
                    armed={activeScan}
                    progress={progress}
                    busy={busy}
                  />
                </div>
              </div>
            </section>
          </div>

          <RadarPanel
            phase={phase}
            blips={blips}
            target={result?.domain ?? (canScan ? liveClass.host : null)}
            stats={stats}
            total={result?.subdomains.length ?? 0}
          />
        </div>

        {/* Results */}
        <section className="mt-12">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2>
              <Label>Results</Label>
            </h2>
            <div className="flex items-center gap-2">
              {result?.report && (
                <button
                  type="button"
                  onClick={downloadReport}
                  className="anim-rise flex h-8 items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 text-[12px] font-medium text-accent outline-none transition-[background-color,transform] duration-150 hover:bg-accent/20 active:scale-[0.97] focus-visible:ring-2 focus-visible:ring-accent-ring"
                >
                  <DownloadGlyph className="h-3.5 w-3.5" />
                  Download report
                </button>
              )}
              {result?.reportError && (
                <span className="text-[12px] text-text-faint" title={result.reportError}>
                  Report unavailable
                </span>
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
            <div className="space-y-10">
              {result.mode === "direct" && !activeScan && (
                <InfoBanner
                  title="Direct target mode"
                  message={`Probing and fingerprinting a single host is an active operation. Enable Active scan and run again to inspect ${result.domain}.`}
                />
              )}

              {showFindings && (
                <FindingsBody
                  result={result}
                  analyzing={analyzing}
                  scanningNuclei={scanningNuclei}
                  nucleiProgress={nucleiProgress}
                />
              )}

              <Evidence
                result={result}
                activeScan={activeScan}
                probing={probing}
                scanningPorts={scanningPorts}
                fingerprinting={fingerprinting}
              />
            </div>
          ) : (
            <ResultPanel dashed>
              <ScanGlyph className="h-7 w-7 text-text-faint" />
              <p className="mt-4 text-sm font-medium text-text-dim">No scan yet</p>
              <p className="mt-1 max-w-xs text-[13px] leading-relaxed text-text-faint">
                Enter a domain or host and run a scan. Findings lead here,
                ordered by severity, with the raw evidence below.
              </p>
            </ResultPanel>
          )}
        </section>
      </main>
    </div>
  );
}

/* ---------- Radar scope (the surface map) ---------- */

type Phase = "idle" | "scanning" | "done";
type BlipTone = "unresolved" | "resolved" | "live" | Exclude<Severity, "INFO">;
type Blip = { id: string; x: number; y: number; tone: BlipTone; delay: number };
type RadarStat = { label: string; value: number | null; tone: string };

const RADAR_LIMIT = 90;
// Rings, as a fraction of the scope radius: the closer to center, the further down the pipeline.
const RING = { live: 0.36, resolved: 0.6, unresolved: 0.84 };

const SEVERITY_RANK: Record<Severity, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const BLIP_DOT: Record<BlipTone, string> = {
  unresolved: "h-1.5 w-1.5 bg-text-ghost",
  resolved: "h-2 w-2 bg-accent shadow-[0_0_8px_var(--accent)]",
  live: "h-2.5 w-2.5 bg-signal-live shadow-[0_0_10px_var(--signal-live)]",
  LOW: "h-2.5 w-2.5 bg-signal-low shadow-[0_0_10px_var(--signal-low)]",
  MEDIUM: "h-2.5 w-2.5 bg-signal-medium shadow-[0_0_10px_var(--signal-medium)]",
  HIGH: "h-3 w-3 bg-signal-high shadow-[0_0_12px_var(--signal-high)]",
  CRITICAL: "h-3 w-3 bg-signal-critical shadow-[0_0_14px_var(--signal-critical)]",
};

const BLIP_PING: Partial<Record<BlipTone, string>> = {
  HIGH: "bg-signal-high",
  CRITICAL: "bg-signal-critical",
};

function hostKey(raw: string): string {
  try {
    return new URL(/^https?:\/\//i.test(raw) ? raw : `http://${raw}`).host.toLowerCase();
  } catch {
    return raw.toLowerCase();
  }
}

const stripPort = (host: string) => host.replace(/:\d+$/, "");

/** FNV-1a: a stable angle per host, so blips don't jump between renders. */
function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function radarBlips(result: ScanState | null, findings: Finding[] | null): Blip[] {
  if (!result) return [];

  const live = new Set<string>();
  for (const h of result.liveHosts ?? []) {
    const k = hostKey(h.url);
    live.add(k);
    live.add(stripPort(k));
  }

  const worst = new Map<string, Severity>();
  for (const f of findings ?? []) {
    const k = stripPort(hostKey(f.host));
    const prev = worst.get(k);
    if (!prev || SEVERITY_RANK[f.severity] > SEVERITY_RANK[prev]) worst.set(k, f.severity);
  }

  return result.subdomains.slice(0, RADAR_LIMIT).map((s, i) => {
    const key = hostKey(s.name);
    const isLive = live.has(key) || live.has(stripPort(key));
    const sev = worst.get(stripPort(key));
    const tone: BlipTone = isLive
      ? sev && sev !== "INFO"
        ? sev
        : "live"
      : s.resolves
        ? "resolved"
        : "unresolved";
    const h = hash(s.name);
    const ring = isLive ? RING.live : s.resolves ? RING.resolved : RING.unresolved;
    const r = (ring + (((h >>> 12) % 100) / 100 - 0.5) * 0.12) * 50;
    const a = ((h % 3600) / 3600) * Math.PI * 2;
    return {
      id: s.name,
      x: 50 + r * Math.sin(a),
      y: 50 - r * Math.cos(a),
      tone,
      delay: Math.min(i, 40) * 30,
    };
  });
}

function RadarPanel({
  phase,
  blips,
  target,
  stats,
  total,
}: {
  phase: Phase;
  blips: Blip[];
  target: string | null;
  stats: RadarStat[];
  total: number;
}) {
  const ticks = Array.from({ length: 72 }, (_, i) => i * 5);
  return (
    <figure className="mx-auto w-full max-w-[380px]">
      <div
        role="img"
        aria-label={
          target
            ? `Surface map for ${target}: ${blips.length} hosts plotted`
            : "Surface map, awaiting a target"
        }
        className="relative aspect-square overflow-hidden rounded-full"
      >
        <svg viewBox="0 0 400 400" className="absolute inset-0 h-full w-full" aria-hidden="true">
          <defs>
            <radialGradient id="scope-fill" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.14" />
              <stop offset="70%" stopColor="var(--accent)" stopOpacity="0.03" />
              <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
            </radialGradient>
          </defs>
          <circle cx="200" cy="200" r="198" fill="url(#scope-fill)" stroke="var(--border-strong)" />
          {[RING.live, RING.resolved, RING.unresolved].map((r) => (
            <circle
              key={r}
              cx="200"
              cy="200"
              r={r * 200}
              fill="none"
              stroke="var(--border)"
              strokeDasharray="2 5"
            />
          ))}
          <line x1="200" y1="4" x2="200" y2="396" stroke="var(--border-soft)" />
          <line x1="4" y1="200" x2="396" y2="200" stroke="var(--border-soft)" />
          {ticks.map((deg) => (
            <line
              key={deg}
              x1="200"
              y1={deg % 45 === 0 ? 4 : 6}
              x2="200"
              y2={deg % 45 === 0 ? 16 : 11}
              stroke={deg % 45 === 0 ? "var(--border-strong)" : "var(--border)"}
              transform={`rotate(${deg} 200 200)`}
            />
          ))}
        </svg>

        {/* Sweep: bright leading edge, trailing afterglow */}
        <div
          aria-hidden="true"
          className="anim-sweep absolute inset-[2px] rounded-full"
          style={{
            animationDuration: phase === "scanning" ? "2.4s" : "9s",
            background:
              "conic-gradient(from 270deg, transparent 0deg, color-mix(in srgb, var(--accent) 5%, transparent) 40deg, color-mix(in srgb, var(--accent) 30%, transparent) 89.5deg, transparent 90deg)",
          }}
        >
          <span className="absolute left-1/2 top-0 h-1/2 w-px -translate-x-1/2 bg-[linear-gradient(to_bottom,var(--accent),color-mix(in_srgb,var(--accent)_10%,transparent))]" />
        </div>

        {blips.map((b) => (
          <span
            key={b.id}
            title={b.id}
            className="anim-blip absolute"
            style={{ left: `${b.x}%`, top: `${b.y}%`, animationDelay: `${b.delay}ms` }}
          >
            {BLIP_PING[b.tone] && (
              <span className={`anim-ping absolute inset-0 rounded-full ${BLIP_PING[b.tone]}`} />
            )}
            <span className={`relative block rounded-full ${BLIP_DOT[b.tone]}`} />
          </span>
        ))}

        {/* Center: the target */}
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <div className="flex flex-col items-center gap-2">
            <span className="relative flex h-3 w-3">
              {phase === "scanning" && (
                <span className="anim-ping absolute inset-0 rounded-full bg-accent" />
              )}
              <span className="relative h-3 w-3 rounded-full bg-accent shadow-[0_0_14px_var(--accent)]" />
            </span>
            <span className="max-w-[170px] truncate rounded-md border border-border-soft bg-canvas/80 px-2 py-0.5 font-mono text-[11px] text-text-dim">
              {target ?? "awaiting target"}
            </span>
          </div>
        </div>
      </div>

      {total > RADAR_LIMIT && (
        <p className="mt-2 text-center text-[11px] text-text-faint">
          Plotting first {RADAR_LIMIT} of {total.toLocaleString()} hosts
        </p>
      )}

      <dl className="mt-6 grid grid-cols-5 gap-1 border-t border-border-soft pt-5 text-center">
        {stats.map((s) => (
          <div key={s.label} className="flex flex-col-reverse gap-1">
            <dt>
              <Label>{s.label}</Label>
            </dt>
            <dd
              className={`font-mono text-[22px] font-semibold leading-none tabular-nums ${
                s.value === null ? "text-text-ghost" : s.tone
              }`}
            >
              {s.value === null ? "–" : s.value.toLocaleString()}
            </dd>
          </div>
        ))}
      </dl>

      <figcaption className="mt-5 flex flex-wrap justify-center gap-x-4 gap-y-1.5 text-[11px] text-text-faint">
        <LegendDot className="bg-text-ghost">No DNS</LegendDot>
        <LegendDot className="bg-accent">Resolves</LegendDot>
        <LegendDot className="bg-signal-live">Live</LegendDot>
        <LegendDot className="bg-signal-critical">At risk</LegendDot>
      </figcaption>
    </figure>
  );
}

function LegendDot({ className, children }: { className: string; children: React.ReactNode }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={`h-1.5 w-1.5 rounded-full ${className}`} />
      {children}
    </span>
  );
}

function StatusPill({ phase, armed }: { phase: Phase; armed: boolean }) {
  const [label, dot] =
    phase === "scanning"
      ? ["Scanning", "bg-accent"]
      : armed
        ? ["Armed", "bg-caution"]
        : ["Passive", "bg-signal-live"];
  return (
    <span className="flex items-center gap-2 rounded-full border border-border bg-surface/70 px-3 py-1">
      <span className="relative flex h-2 w-2">
        {(phase === "scanning" || armed) && (
          <span className={`anim-ping absolute inset-0 rounded-full ${dot}`} />
        )}
        <span className={`relative h-2 w-2 rounded-full ${dot}`} />
      </span>
      <Label className="text-text-dim">{label}</Label>
    </span>
  );
}

/* ---------- Pipeline rail ---------- */

type StageState = "idle" | "locked" | "skipped" | "running" | "done" | "error";
type Stage = { name: string; state: StageState };

const STAGE_TEXT: Record<StageState, string> = {
  idle: "text-text-dim",
  locked: "text-text-ghost",
  skipped: "text-text-ghost line-through",
  running: "text-accent",
  done: "text-text",
  error: "text-signal-critical",
};

const STAGE_SR: Record<StageState, string> = {
  idle: "ready",
  locked: "needs active scan",
  skipped: "skipped",
  running: "running",
  done: "done",
  error: "failed",
};

/** Four stages split by the authorization line: passive on the left, active on the right. */
function StageRail({
  stages,
  armed,
  progress,
  busy,
}: {
  stages: Stage[];
  armed: boolean;
  progress: number;
  busy: boolean;
}) {
  const [passive, ...active] = stages;
  return (
    <div className="mt-3 border-t border-border-soft pt-4">
      <ol aria-label="Scan pipeline" className="flex flex-wrap items-center gap-x-5 gap-y-2.5">
        <StageStep index={1} stage={passive} />
        <li
          aria-hidden="true"
          title="Authorization line"
          className={`h-5 w-px transition-colors duration-150 ${
            armed ? "bg-caution shadow-[0_0_8px_var(--caution)]" : "bg-border-strong"
          }`}
        />
        {active.map((stage, i) => (
          <StageStep key={stage.name} index={i + 2} stage={stage} />
        ))}
      </ol>
      <div aria-hidden="true" className="mt-4 h-[3px] overflow-hidden rounded-full bg-surface-raised">
        <div
          className={`h-full origin-left rounded-full transition-transform duration-500 ease-[cubic-bezier(0.23,1,0.32,1)] ${
            busy
              ? "anim-shimmer bg-[linear-gradient(90deg,var(--accent),var(--accent-2),var(--accent))]"
              : "bg-[linear-gradient(90deg,var(--accent),var(--accent-2))]"
          }`}
          style={{ transform: `scaleX(${busy ? Math.max(progress, 0.06) : progress})` }}
        />
      </div>
    </div>
  );
}

function StageStep({ index, stage }: { index: number; stage: Stage }) {
  const { name, state } = stage;
  return (
    <li
      aria-current={state === "running" ? "step" : undefined}
      className={`flex items-center gap-2 text-[13px] transition-colors duration-150 ${STAGE_TEXT[state]}`}
    >
      <StepMark index={index} state={state} />
      <span>{name}</span>
      <span className="sr-only">({STAGE_SR[state]})</span>
    </li>
  );
}

function StepMark({ index, state }: { index: number; state: StageState }) {
  if (state === "running") return <Spinner className="h-4 w-4" />;
  if (state === "done") {
    return (
      <span className="grid h-4 w-4 place-items-center rounded-full bg-signal-live/15 text-signal-live">
        <CheckGlyph className="h-2.5 w-2.5" />
      </span>
    );
  }
  return (
    <span
      className={`grid h-4 w-4 place-items-center rounded-full border font-mono text-[9px] leading-none tabular-nums ${
        state === "error" ? "border-signal-critical/50" : "border-border-strong"
      }`}
    >
      {state === "error" ? "!" : index}
    </span>
  );
}

/** The whole row is the switch: label, state and description are all one hit area. */
function SwitchRow({
  id,
  checked,
  onChange,
  title,
  tag,
  description,
}: {
  id: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  title: string;
  tag: React.ReactNode;
  description: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-labelledby={`${id}-label`}
      aria-describedby={`${id}-desc`}
      onClick={() => onChange(!checked)}
      className="group flex w-full items-start justify-between gap-4 rounded-lg py-2.5 text-left outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
    >
      <span className="min-w-0">
        <span className="flex items-center gap-2">
          <span id={`${id}-label`} className="text-sm font-medium text-text">
            {title}
          </span>
          {tag}
        </span>
        <span
          id={`${id}-desc`}
          className="mt-1 block text-[13px] leading-relaxed text-text-dim"
        >
          {description}
        </span>
      </span>
      <span
        aria-hidden="true"
        className={`mt-0.5 inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors duration-150 ${
          checked
            ? "border-caution/60 bg-caution/20"
            : "border-border-strong bg-surface-raised group-hover:border-text-faint/60"
        }`}
      >
        <span
          className={`inline-block h-4 w-4 rounded-full transition-transform duration-150 ${
            checked ? "translate-x-5 bg-caution" : "translate-x-1 bg-text-faint"
          }`}
        />
      </span>
    </button>
  );
}

const INTENSITY_ORDER: ScanIntensity[] = ["polite", "normal", "aggressive"];

/** Segmented control over native radios: one setting paces every active stage. */
function IntensityControl({
  value,
  onChange,
}: {
  value: ScanIntensity;
  onChange: (value: ScanIntensity) => void;
}) {
  const p = INTENSITY_PROFILES[value];
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2.5 py-3">
      <div className="min-w-0">
        <span id="intensity-label" className="text-sm font-medium text-text">
          Scan intensity
        </span>
        <span className="mt-1 block font-mono text-[11px] tabular-nums text-text-faint">
          {p.concurrency} parallel · {p.delayMs}ms spacing · nuclei {p.nucleiRateLimit} req/s
        </span>
      </div>
      <div
        role="radiogroup"
        aria-labelledby="intensity-label"
        className="flex rounded-lg border border-border bg-control p-0.5"
      >
        {INTENSITY_ORDER.map((key) => (
          <label
            key={key}
            className={`flex h-9 cursor-pointer items-center rounded-md px-3.5 text-[12px] font-medium transition-colors duration-150 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-accent-ring ${
              value === key
                ? key === "aggressive"
                  ? "bg-caution/15 text-caution shadow-[0_0_0_1px_var(--caution-border)]"
                  : "bg-surface-raised text-text shadow-[0_0_0_1px_var(--border-strong)]"
                : "text-text-faint hover:text-text-dim"
            }`}
          >
            <input
              type="radio"
              name="intensity"
              value={key}
              checked={value === key}
              onChange={() => onChange(key)}
              className="sr-only"
            />
            {INTENSITY_PROFILES[key].label}
          </label>
        ))}
      </div>
    </div>
  );
}

/* ---------- Findings (the payoff) ---------- */

type Tone = "critical" | "high" | "medium" | "low" | "neutral" | "live";

const TONE: Record<Tone, string> = {
  critical: "border-signal-critical/45 bg-signal-critical/[0.12] text-signal-critical",
  high: "border-signal-high/40 bg-signal-high/[0.1] text-signal-high",
  medium: "border-signal-medium/35 bg-signal-medium/[0.08] text-signal-medium",
  low: "border-signal-low/40 bg-signal-low/[0.1] text-signal-low",
  neutral: "border-border bg-surface-raised text-text-dim",
  live: "border-signal-live/30 bg-signal-live/[0.08] text-signal-live",
};

const SEVERITY_TONE: Record<Severity, Tone> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "neutral",
};

const SEVERITY_BAR: Record<Severity, string> = {
  CRITICAL: "bg-signal-critical",
  HIGH: "bg-signal-high",
  MEDIUM: "bg-signal-medium",
  LOW: "bg-signal-low",
  INFO: "bg-text-faint/50",
};

const LEVEL_TEXT: Record<ReturnType<typeof riskLevel>["tone"], string> = {
  critical: "text-signal-critical",
  high: "text-signal-high",
  elevated: "text-signal-medium",
  low: "text-signal-low",
  clean: "text-signal-live",
};

const SEVERITY_TEXT: Record<Severity, string> = {
  CRITICAL: "text-signal-critical",
  HIGH: "text-signal-high",
  MEDIUM: "text-signal-medium",
  LOW: "text-signal-low",
  INFO: "text-text-dim",
};

const SEVERITY_EDGE: Record<Severity, string> = {
  CRITICAL: "shadow-[inset_3px_0_0_var(--signal-critical)]",
  HIGH: "shadow-[inset_3px_0_0_var(--signal-high)]",
  MEDIUM: "shadow-[inset_3px_0_0_var(--signal-medium)]",
  LOW: "shadow-[inset_3px_0_0_var(--signal-low)]",
  INFO: "shadow-[inset_3px_0_0_var(--border-strong)]",
};

const SEVERITY_STROKE: Record<Severity, string> = {
  CRITICAL: "var(--signal-critical)",
  HIGH: "var(--signal-high)",
  MEDIUM: "var(--signal-medium)",
  LOW: "var(--signal-low)",
  INFO: "var(--text-ghost)",
};

const LEVEL_VAR: Record<ReturnType<typeof riskLevel>["tone"], string> = {
  critical: "var(--signal-critical)",
  high: "var(--signal-high)",
  elevated: "var(--signal-medium)",
  low: "var(--signal-low)",
  clean: "var(--signal-live)",
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

  // Merge Phase 5 (analysis) findings with nuclei (Stage 4b) findings, deduped.
  const merged = sortFindings(
    dedupeFindings([
      ...result.findings,
      ...(result.nuclei?.findings ?? []),
      ...result.portFindings,
    ]),
  );
  const hostCount = result.liveHosts?.length ?? 0;

  return (
    <div>
      <RiskHeadline findings={merged} hostCount={hostCount} />

      {scanningNuclei && (
        <Notice>
          <Spinner className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
          <p>
            Running <span className="font-mono text-text">nuclei</span> deep
            vulnerability scan. Findings stream in as they&apos;re found.{" "}
            <span className="text-text-faint">
              {nucleiProgress ?? "Starting up… the first run downloads templates."}
            </span>
          </p>
        </Notice>
      )}

      {!scanningNuclei && result.nuclei && result.nuclei.status !== "ok" && (
        <Notice>
          <WarnGlyph className="mt-0.5 h-4 w-4 shrink-0 text-text-faint" />
          <p>
            <span className="font-medium text-text">
              {result.nuclei.status === "partial"
                ? "Deep scan partial —"
                : "nuclei skipped."}
            </span>{" "}
            {result.nuclei.message ?? "Showing header/path findings only."}
          </p>
        </Notice>
      )}

      {!scanningNuclei && result.nucleiError && (
        <Notice>
          <WarnGlyph className="mt-0.5 h-4 w-4 shrink-0 text-text-faint" />
          <p>
            <span className="font-medium text-text">nuclei error.</span>{" "}
            {result.nucleiError} Showing header/path findings only.
          </p>
        </Notice>
      )}

      {merged.length === 0 ? (
        <EmptyNote>No findings. Nothing notable surfaced on these hosts.</EmptyNote>
      ) : (
        <TableFrame fit>
          <thead>
            <tr className="border-b border-border">
              <Th className="w-24 sm:w-28">Severity</Th>
              <Th>Finding</Th>
              <Th className="hidden w-[28%] sm:table-cell">Host</Th>
            </tr>
          </thead>
          <tbody>
            {merged.map((f, i) => (
              <tr key={i} className={ROW} style={rowDelay(i)}>
                <td className={`px-4 py-3 ${SEVERITY_EDGE[f.severity]}`}>
                  <Chip tone={SEVERITY_TONE[f.severity]}>{f.severity}</Chip>
                </td>
                <td className="px-4 py-3">
                  <p className="font-medium text-text">{f.title}</p>
                  <p className="mt-0.5 leading-relaxed text-text-dim text-pretty">
                    {f.description}
                  </p>
                  <p className="mt-1.5 text-[12px] leading-relaxed text-text-faint text-pretty">
                    <span className="font-medium text-text-dim">Fix</span>{" "}
                    {f.recommendation}
                  </p>
                  <p className="mt-1.5 font-mono text-[11px] text-text-faint break-all sm:hidden">
                    {f.host}
                  </p>
                </td>
                <td className="hidden px-4 py-3 font-mono text-[12px] text-text-dim break-all sm:table-cell">
                  {f.host}
                </td>
              </tr>
            ))}
          </tbody>
        </TableFrame>
      )}
    </div>
  );
}

/** Level leads, the donut explains it, the raw weighted score is a footnote. */
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
  const byHost = Object.entries(riskScoreByHost(findings)).sort(
    (a, b) => b[1] - a[1],
  );
  const total = findings.length;
  const hosts = `${hostCount} ${hostCount === 1 ? "host" : "hosts"}`;
  const glow = LEVEL_VAR[level.tone];

  return (
    <div
      className="anim-rise mb-4 overflow-hidden rounded-2xl border border-border p-6"
      style={{
        background: `radial-gradient(520px 220px at 0% 0%, color-mix(in srgb, ${glow} 16%, transparent), transparent 70%), var(--surface)`,
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-8">
        <div className="min-w-0">
          <Label>Overall risk</Label>
          <p
            className={`mt-2 text-[52px] font-semibold leading-none tracking-[-0.035em] ${LEVEL_TEXT[level.tone]}`}
            style={{ textShadow: `0 0 40px color-mix(in srgb, ${glow} 45%, transparent)` }}
          >
            {level.tone === "clean" ? "Clean" : `${level.label} risk`}
          </p>
          <p className="mt-3 text-[13px] text-text-dim">
            {total === 0
              ? `No findings across ${hosts}`
              : `${total} ${total === 1 ? "finding" : "findings"} across ${hosts}`}
            <span className="text-text-faint">
              {" "}
              · weighted score{" "}
              <span className="font-mono tabular-nums text-text-dim">{score}</span>
            </span>
          </p>
          {total > 0 && (
            <div className="mt-5 flex flex-wrap gap-x-5 gap-y-1.5 text-[12px]">
              {SEVERITY_SORT.map((s) => (
                <span
                  key={s}
                  className={`flex items-center gap-1.5 ${
                    counts[s] > 0 ? "text-text-dim" : "text-text-ghost"
                  }`}
                >
                  <span
                    className={`h-2 w-2 rounded-full ${
                      counts[s] > 0 ? SEVERITY_BAR[s] : "bg-text-ghost/50"
                    }`}
                  />
                  <span className={`font-mono tabular-nums ${counts[s] > 0 ? "text-text" : ""}`}>
                    {counts[s]}
                  </span>
                  {s.toLowerCase()}
                </span>
              ))}
            </div>
          )}
        </div>
        {total > 0 && <SeverityDonut counts={counts} total={total} />}
      </div>

      {hostCount > 1 && byHost.length > 0 && (
        <div className="mt-6 border-t border-border-soft pt-4">
          <Label>By host</Label>
          <div className="mt-2 space-y-1.5">
            {byHost.map(([host, s]) => (
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

function SeverityDonut({
  counts,
  total,
}: {
  counts: Record<Severity, number>;
  total: number;
}) {
  const R = 52;
  const C = 2 * Math.PI * R;
  const GAP = total > 1 ? 3 : 0;
  let offset = 0;
  return (
    <div className="relative h-36 w-36 shrink-0">
      <svg
        viewBox="0 0 140 140"
        className="h-full w-full -rotate-90"
        role="img"
        aria-label={SEVERITY_SORT.map((s) => `${counts[s]} ${s.toLowerCase()}`).join(", ")}
      >
        <circle cx="70" cy="70" r={R} fill="none" stroke="var(--surface-raised)" strokeWidth="14" />
        {SEVERITY_SORT.filter((s) => counts[s] > 0).map((s) => {
          const len = (counts[s] / total) * C;
          const arc = (
            <circle
              key={s}
              cx="70"
              cy="70"
              r={R}
              fill="none"
              stroke={SEVERITY_STROKE[s]}
              strokeWidth="14"
              strokeDasharray={`${Math.max(len - GAP, 1)} ${C}`}
              strokeDashoffset={-offset}
              style={{ filter: `drop-shadow(0 0 6px ${SEVERITY_STROKE[s]})` }}
            />
          );
          offset += len;
          return arc;
        })}
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <p className="font-mono text-[28px] font-semibold leading-none tabular-nums text-text">
            {total}
          </p>
          <p className="mt-1 text-[11px] text-text-faint">
            {total === 1 ? "finding" : "findings"}
          </p>
        </div>
      </div>
    </div>
  );
}

/* ---------- Evidence (stages 1–3, steps back once findings exist) ---------- */

function Evidence({
  result,
  activeScan,
  probing,
  scanningPorts,
  fingerprinting,
}: {
  result: ScanState;
  activeScan: boolean;
  probing: boolean;
  scanningPorts: boolean;
  fingerprinting: boolean;
}) {
  const showDiscovery = result.mode === "domain";
  if (!showDiscovery && !activeScan) return null;

  const settled = result.findings !== null;
  const { subdomains, liveHosts, fingerprints } = result;
  const resolved = subdomains.filter((s) => s.resolves).length;

  let hostsSummary: string;
  if (probing) hostsSummary = "Probing…";
  else if (result.probeError) hostsSummary = "Probe failed";
  else if (liveHosts === null) hostsSummary = "Not run";
  else {
    hostsSummary = `${liveHosts.length} responding`;
    if (fingerprinting) hostsSummary += " · fingerprinting…";
    else if (fingerprints) {
      const techs = fingerprints.reduce((n, fp) => n + fp.technologies.length, 0);
      const paths = fingerprints.reduce((n, fp) => n + fp.exposedPaths.length, 0);
      hostsSummary += ` · ${techs} ${techs === 1 ? "technology" : "technologies"} · ${paths} exposed ${paths === 1 ? "path" : "paths"}`;
    }
  }

  let portsSummary: string;
  if (scanningPorts) portsSummary = "Scanning…";
  else if (result.portsError) portsSummary = "Port scan failed";
  else if (result.openPorts === null) portsSummary = "Not run";
  else {
    const flagged = result.portFindings.length;
    portsSummary = `${result.openPorts.length} open`;
    if (flagged > 0) portsSummary += ` · ${flagged} flagged`;
  }

  return (
    <div>
      {settled && (
        <h3 className="mb-3">
          <Label>Evidence</Label>
        </h3>
      )}
      <div className="anim-rise divide-y divide-border-soft overflow-hidden rounded-2xl border border-border bg-surface">
        {showDiscovery && (
          <EvidenceSection
            index={1}
            title="Discovery"
            summary={
              subdomains.length === 0
                ? "No subdomains found"
                : `${subdomains.length.toLocaleString()} subdomains · ${resolved.toLocaleString()} resolve`
            }
            open={!activeScan}
          >
            <DiscoveryTable result={result} />
          </EvidenceSection>
        )}
        {activeScan && (
          <EvidenceSection
            index={2}
            title="Live hosts"
            summary={hostsSummary}
            open={!settled}
          >
            <LiveHostsBody
              result={result}
              probing={probing}
              fingerprinting={fingerprinting}
            />
          </EvidenceSection>
        )}
        {activeScan && (
          <EvidenceSection
            index={3}
            title="Open ports"
            summary={portsSummary}
            open={!settled}
          >
            <PortsBody result={result} scanningPorts={scanningPorts} />
          </EvidenceSection>
        )}
      </div>
    </div>
  );
}

function EvidenceSection({
  index,
  title,
  summary,
  open,
  children,
}: {
  index: number;
  title: string;
  summary: string;
  open: boolean;
  children: React.ReactNode;
}) {
  return (
    <details open={open} className="group/ev">
      <summary className="flex min-h-12 cursor-pointer list-none items-center gap-3 px-4 py-3 outline-none transition-colors duration-150 hover:bg-row-hover focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent-ring [&::-webkit-details-marker]:hidden">
        <span className="font-mono text-[11px] tabular-nums text-text-faint">
          {String(index).padStart(2, "0")}
        </span>
        <span className="text-sm font-medium text-text">{title}</span>
        <span className="min-w-0 flex-1 truncate text-[13px] text-text-dim">
          {summary}
        </span>
        <ChevronGlyph className="h-4 w-4 shrink-0 text-text-faint transition-transform duration-150 group-open/ev:rotate-180" />
      </summary>
      <div className="border-t border-border-soft">{children}</div>
    </details>
  );
}

const ROW_LIMIT = 25;

function DiscoveryTable({ result }: { result: ScanState }) {
  const [showAll, setShowAll] = useState(false);
  const { domain, subdomains } = result;
  const total = subdomains.length;

  if (total === 0) {
    return (
      <p className="px-4 py-5 text-[13px] text-text-faint">
        Certificate transparency returned no names for{" "}
        <span className="font-mono text-text-dim">{domain}</span>.
      </p>
    );
  }

  const rows = showAll ? subdomains : subdomains.slice(0, ROW_LIMIT);

  return (
    <>
      {total > DNS_RESOLVE_CAP && (
        <p className="px-4 pt-3 text-[12px] leading-relaxed text-text-faint">
          DNS resolution capped at {DNS_RESOLVE_CAP} for responsiveness; the
          remaining {(total - DNS_RESOLVE_CAP).toLocaleString()} are listed
          without records.
        </p>
      )}
      <TableFrame bare>
        <thead>
          <tr className="border-b border-border">
            <th className="w-10 px-4 py-2.5" aria-label="Resolves" />
            <Th>Subdomain</Th>
            <Th>A</Th>
            <Th>CNAME</Th>
            <Th>MX</Th>
            <Th>TXT</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((s, i) => (
            <tr key={s.name} className={ROW} style={rowDelay(i)}>
              <td className="px-4 py-2.5">
                <Dot resolves={s.resolves} />
              </td>
              <td className="px-4 py-2.5 font-mono text-text break-all">{s.name}</td>
              <td className="whitespace-nowrap px-4 py-2.5 font-mono text-text-dim">
                <RecordList values={s.records.A} />
              </td>
              <td className="px-4 py-2.5 font-mono text-text-dim break-all">
                <RecordList values={s.records.CNAME} />
              </td>
              <td className="whitespace-nowrap px-4 py-2.5 font-mono text-text-dim">
                <RecordList values={s.records.MX} />
              </td>
              <td className="max-w-[360px] px-4 py-2.5 font-mono text-[12px] text-text-dim break-all">
                <RecordList values={s.records.TXT} />
              </td>
            </tr>
          ))}
        </tbody>
      </TableFrame>
      {total > ROW_LIMIT && (
        <ShowAllButton
          expanded={showAll}
          total={total}
          onClick={() => setShowAll((v) => !v)}
        />
      )}
    </>
  );
}

function LiveHostsBody({
  result,
  probing,
  fingerprinting,
}: {
  result: ScanState;
  probing: boolean;
  fingerprinting: boolean;
}) {
  const [showAll, setShowAll] = useState(false);

  if (probing) {
    return (
      <InlineLoading
        title="Probing live hosts…"
        detail="Sending HTTP/HTTPS requests to resolved hosts (5s timeout, 10 at a time)."
      />
    );
  }
  if (result.probeError) {
    return (
      <div className="p-4">
        <ErrorBanner title="Probe failed" message={result.probeError} />
      </div>
    );
  }

  const hosts = result.liveHosts;
  if (hosts === null) {
    return <p className="px-4 py-5 text-[13px] text-text-faint">Re-run the scan to probe live hosts.</p>;
  }
  if (hosts.length === 0) {
    return <p className="px-4 py-5 text-[13px] text-text-faint">No live hosts responded.</p>;
  }

  const fpByHost = new Map<string, Fingerprint>(
    (result.fingerprints ?? []).map((fp) => [fp.host, fp]),
  );
  const rows = showAll ? hosts : hosts.slice(0, ROW_LIMIT);

  return (
    <>
      {result.fingerprintError && (
        <div className="px-4 pt-4">
          <ErrorBanner title="Fingerprint failed" message={result.fingerprintError} />
        </div>
      )}
      <TableFrame bare>
        <thead>
          <tr className="border-b border-border">
            <Th className="w-20">Status</Th>
            <Th>Host</Th>
            <Th>Title</Th>
            <Th>Server</Th>
            <Th className="w-[34%]">Stack</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((h, i) => (
            <tr key={`${h.url}-${i}`} className={ROW} style={rowDelay(i)}>
              <td className="px-4 py-3">
                <Tag tone={h.status < 300 ? "live" : "neutral"}>{h.status}</Tag>
              </td>
              <td className="px-4 py-3 font-mono text-text break-all">
                {h.url}
                <span className="mt-0.5 block text-[11px] tabular-nums text-text-faint">
                  {h.responseTimeMs}ms
                  {h.contentLength != null
                    ? ` · ${h.contentLength.toLocaleString()} B`
                    : ""}
                  {h.ip ? ` · ${h.ip}` : ""}
                </span>
              </td>
              <td className="px-4 py-3 text-text-dim break-all">
                {h.title || <span className="text-text-faint">—</span>}
              </td>
              <td className="px-4 py-3 font-mono text-text-dim break-all">
                {h.server || h.xPoweredBy || <span className="text-text-faint">—</span>}
                {h.server && h.xPoweredBy && (
                  <span className="mt-0.5 block text-[11px] text-text-faint">
                    via {h.xPoweredBy}
                  </span>
                )}
              </td>
              <td className="px-4 py-3">
                <StackCell fp={fpByHost.get(h.url)} pending={fingerprinting} />
              </td>
            </tr>
          ))}
        </tbody>
      </TableFrame>
      {hosts.length > ROW_LIMIT && (
        <ShowAllButton
          expanded={showAll}
          total={hosts.length}
          onClick={() => setShowAll((v) => !v)}
        />
      )}
    </>
  );
}

function PortsBody({
  result,
  scanningPorts,
}: {
  result: ScanState;
  scanningPorts: boolean;
}) {
  const [showAll, setShowAll] = useState(false);

  if (scanningPorts) {
    return (
      <InlineLoading
        title="Scanning ports…"
        detail="TCP-connect scan over ~90 common ports per host, paced by the intensity setting."
      />
    );
  }
  if (result.portsError) {
    return (
      <div className="p-4">
        <ErrorBanner title="Port scan failed" message={result.portsError} />
      </div>
    );
  }

  const ports = result.openPorts;
  if (ports === null) {
    return (
      <p className="px-4 py-5 text-[13px] text-text-faint">
        The port scan runs once live hosts are found.
      </p>
    );
  }
  if (ports.length === 0) {
    return (
      <p className="px-4 py-5 text-[13px] text-text-faint">
        No open ports found on the scanned hosts.
      </p>
    );
  }

  // Port findings are keyed host:port; anything flagged carries its severity.
  const severityByHostPort = new Map(
    result.portFindings.map((f) => [f.host, f.severity]),
  );
  const rows = showAll ? ports : ports.slice(0, ROW_LIMIT);

  return (
    <>
      <TableFrame bare>
        <thead>
          <tr className="border-b border-border">
            <Th className="w-24">Port</Th>
            <Th>Service</Th>
            <Th>Host</Th>
            <Th className="w-28">Risk</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((p, i) => {
            const sev = severityByHostPort.get(`${p.host}:${p.port}`);
            return (
              <tr key={`${p.host}-${p.port}-${i}`} className={ROW} style={rowDelay(i)}>
                <td
                  className={`px-4 py-2.5 font-mono tabular-nums text-text ${
                    sev ? SEVERITY_EDGE[sev] : ""
                  }`}
                >
                  {p.port}
                </td>
                <td className={`px-4 py-2.5 ${sev ? "font-medium text-text" : "text-text-dim"}`}>
                  {p.service}
                </td>
                <td className="px-4 py-2.5 font-mono text-[12px] text-text-dim break-all">
                  {p.host}
                </td>
                <td className="px-4 py-2.5">
                  {sev ? (
                    <Chip tone={SEVERITY_TONE[sev]}>{sev}</Chip>
                  ) : (
                    <span className="text-[12px] text-text-faint">Open</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </TableFrame>
      {ports.length > ROW_LIMIT && (
        <ShowAllButton
          expanded={showAll}
          total={ports.length}
          onClick={() => setShowAll((v) => !v)}
        />
      )}
    </>
  );
}

function StackCell({ fp, pending }: { fp?: Fingerprint; pending: boolean }) {
  if (pending) {
    return (
      <span className="flex items-center gap-2 text-[12px] text-text-faint">
        <Spinner className="h-3.5 w-3.5 text-accent" />
        Fingerprinting…
      </span>
    );
  }
  if (!fp) return <span className="text-text-faint">—</span>;
  if (fp.technologies.length === 0 && fp.exposedPaths.length === 0) {
    return <span className="text-[12px] text-text-faint">Nothing detected</span>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {fp.technologies.map((t, i) => (
        <Tag key={`t${i}`}>
          {t.name}
          {t.version ? <span className="text-text-faint">{t.version}</span> : null}
        </Tag>
      ))}
      {/* Exposed paths carry the severity analysis will assign them. */}
      {fp.exposedPaths.map((p, i) => (
        <Tag key={`p${i}`} tone={/^\/\.(git|env)/.test(p) ? "high" : "medium"}>
          {p}
        </Tag>
      ))}
    </div>
  );
}

/* ---------- Shared pieces ---------- */

const LABEL = "font-mono text-[11px] uppercase tracking-[0.16em]";
const ROW =
  "anim-rise border-b border-border-soft align-top transition-colors duration-150 last:border-0 hover:bg-row-hover";
const rowDelay = (i: number) => ({ animationDelay: `${Math.min(i, 12) * 35}ms` });

/** The one metadata voice: section labels, column heads, small state readouts. */
function Label({
  children,
  className = "text-text-faint",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <span className={`${LABEL} ${className}`}>{children}</span>;
}

/** Bordered uppercase token for classifications (severity, mode). */
function Chip({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-[0.08em] ${TONE[tone]}`}
    >
      {children}
    </span>
  );
}

/** Bordered literal value (tech names, paths, status codes); never uppercased. */
function Tag({
  tone = "neutral",
  children,
}: {
  tone?: Tone;
  children: React.ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[11px] tabular-nums ${TONE[tone]}`}
    >
      {children}
    </span>
  );
}

/** `fit` tables reflow to the viewport; the rest keep a min width and scroll sideways. */
function TableFrame({
  children,
  bare = false,
  fit = false,
}: {
  children: React.ReactNode;
  bare?: boolean;
  fit?: boolean;
}) {
  return (
    <div
      className={`overflow-x-auto ${
        bare ? "" : "rounded-2xl border border-border bg-surface"
      }`}
    >
      <table
        className={`w-full border-collapse text-[13px] ${fit ? "" : "min-w-[640px]"}`}
      >
        {children}
      </table>
    </div>
  );
}

function Th({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <th
      scope="col"
      className={`px-4 py-2.5 text-left font-medium text-text-faint ${LABEL} ${className}`}
    >
      {children}
    </th>
  );
}

function ShowAllButton({
  expanded,
  total,
  onClick,
}: {
  expanded: boolean;
  total: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex h-11 w-full items-center justify-center border-t border-border-soft text-[13px] text-accent outline-none transition-colors duration-150 hover:bg-row-hover hover:text-accent-hover focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent-ring"
    >
      {expanded ? `Show first ${ROW_LIMIT}` : `Show all ${total.toLocaleString()}`}
    </button>
  );
}

function StageLoading({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface">
      <InlineLoading title={title} detail={detail} />
    </div>
  );
}

function InlineLoading({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="flex items-center gap-3 px-5 py-6">
      <Spinner className="h-5 w-5 shrink-0 text-accent" />
      <div>
        <p className="text-sm font-medium text-text-dim">{title}</p>
        <p className="mt-0.5 text-[13px] leading-relaxed text-text-faint">
          {detail}
        </p>
      </div>
    </div>
  );
}

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-4 flex gap-2.5 rounded-lg border border-border bg-surface px-3.5 py-2.5 text-[13px] leading-relaxed text-text-dim">
      {children}
    </div>
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
        resolves ? "bg-accent shadow-[0_0_6px_var(--accent)]" : "bg-text-ghost"
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
  return (
    <Chip tone="neutral">{mode === "direct" ? "Direct target" : "Domain enumeration"}</Chip>
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
      className={`flex min-h-[220px] flex-col items-center justify-center rounded-xl border px-6 py-12 text-center ${
        dashed ? "border-dashed border-border" : "border-border bg-surface"
      }`}
    >
      {children}
    </div>
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

function ShieldMark({ className }: { className?: string }) {
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
      <path d="M12 2.5 4.5 5.5v6c0 4.5 3.1 8 7.5 10 4.4-2 7.5-5.5 7.5-10v-6L12 2.5Z" />
      <path d="m9 12 2.2 2.2L15.5 10" />
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

function CheckGlyph({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={3}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="m5 12.5 4.5 4.5L19 7.5" />
    </svg>
  );
}

function ChevronGlyph({ className }: { className?: string }) {
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
      <path d="m6 9 6 6 6-6" />
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
