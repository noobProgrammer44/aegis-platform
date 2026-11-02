import type { DiscoveredDomainInput } from "@/lib/db/repos/discovered-domains";
import { analyze } from "@/lib/recon/analysis";
import { discover } from "@/lib/recon/discovery";
import { fingerprint } from "@/lib/recon/fingerprint";
import type { ScanIntensity } from "@/lib/recon/intensity";
import { runNucleiStream } from "@/lib/recon/nuclei";
import { scanPorts } from "@/lib/recon/ports";
import { probe } from "@/lib/recon/probe";
import type { DetectedRisk, ScanType, Target } from "@/types/aegis";
import type { Finding, LiveHost } from "@/types/recon";
import { SCANNER_CATALOG, type ScannerInfo } from "./catalog";
import { toDetectedRisks } from "./findings";
import { discoveryDomain, hostsForTarget, toSubdomains } from "./target-hosts";

/**
 * Scanner adapters: each wraps existing recon stages (lib/recon) behind one interface
 * the runner understands. Active scanners are only called after the gate allows them.
 */

export interface ScannerContext {
  target: Target;
  intensity: ScanIntensity;
  signal: AbortSignal;
  progress: (message: string) => void;
}

export interface ScannerOutput {
  risks: readonly DetectedRisk[];
  discovered: readonly DiscoveredDomainInput[];
  /** Raw stage output, stored as the scan's downloadable results. */
  raw: unknown;
  /** Why this target was not scanned (not applicable, tool unavailable). */
  skipped?: string;
}

export interface Scanner extends ScannerInfo {
  run(ctx: ScannerContext): Promise<ScannerOutput>;
}

const EMPTY = { risks: [], discovered: [] } as const;

/** Port scanning needs hostnames, not HTTP liveness, so hosts are passed as stubs. */
const asHostStub = (host: string): LiveHost => ({
  url: `http://${host}/`,
  status: 0,
  title: "",
  server: "",
  ip: "",
  responseTimeMs: 0,
  headers: {},
});

const discovery: Scanner = {
  ...SCANNER_CATALOG.DISCOVERY,
  async run({ target, progress }) {
    const domain = discoveryDomain(target);
    if (!domain) return { ...EMPTY, raw: null, skipped: "Subdomain discovery needs a domain target." };
    progress(`Enumerating subdomains of ${domain}`);
    const subdomains = await discover(domain);
    const discovered = subdomains
      .filter((s) => s.name !== domain)
      .map((s) => ({
        name: s.name,
        viaTargetId: target.id,
        viaTarget: target.target,
        resolves: s.resolves,
        records: s.records as Record<string, string[]>,
      }));
    return { risks: [], discovered, raw: subdomains };
  },
};

const surface: Scanner = {
  ...SCANNER_CATALOG.SURFACE,
  async run({ target, intensity, progress }) {
    progress("Probing for live web services");
    const live = await probe(toSubdomains(hostsForTarget(target)), true, intensity);
    if (live.length === 0) return { ...EMPTY, raw: { live: [] } };
    progress(`Fingerprinting ${live.length} live host${live.length === 1 ? "" : "s"}`);
    const fingerprints = await fingerprint(live, true, intensity);
    progress("Analyzing the surface");
    const findings = await analyze(live, fingerprints, true);
    return {
      risks: toDetectedRisks("SURFACE", target.id, findings),
      discovered: [],
      raw: { live, fingerprints, findings },
    };
  },
};

const ports: Scanner = {
  ...SCANNER_CATALOG.NMAP,
  async run({ target, intensity, progress }) {
    const hosts = hostsForTarget(target).map(asHostStub);
    progress(`Checking common ports on ${hosts.length} host${hosts.length === 1 ? "" : "s"}`);
    const result = await scanPorts(hosts, true, intensity);
    return {
      risks: toDetectedRisks("NMAP", target.id, result.findings),
      discovered: [],
      raw: result,
    };
  },
};

const nuclei: Scanner = {
  ...SCANNER_CATALOG.NUCLEI,
  async run({ target, intensity, signal, progress }) {
    progress("Probing for live web services");
    const live = await probe(toSubdomains(hostsForTarget(target)), true, intensity);
    if (live.length === 0) return { ...EMPTY, raw: { live: [] } };
    const findings: Finding[] = [];
    const status = await runNucleiStream(
      live,
      { onFinding: (f) => findings.push(f), onProgress: progress },
      { signal, intensity },
    );
    if (status.status === "unavailable" || status.status === "error") {
      return { ...EMPTY, raw: { status }, skipped: status.message ?? "nuclei could not run." };
    }
    return {
      risks: toDetectedRisks("NUCLEI", target.id, findings),
      discovered: [],
      raw: { status, findings },
    };
  },
};

export const SCANNERS: Partial<Record<ScanType, Scanner>> = {
  DISCOVERY: discovery,
  SURFACE: surface,
  NMAP: ports,
  NUCLEI: nuclei,
};
