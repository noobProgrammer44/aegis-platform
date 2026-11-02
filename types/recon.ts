/**
 * Core domain types for the Aegis recon pipeline.
 * Shared across the stages: discovery → live probe → port scan → crawl/fingerprint → surface analysis.
 */

import type { ScanIntensity } from "@/lib/recon/intensity";

/** DNS records collected for a subdomain during discovery. */
export interface Subdomain {
  name: string;
  /** True if at least one DNS record resolved; false for unresolved (empty records). */
  resolves: boolean;
  records: {
    A?: string[];
    AAAA?: string[];
    CNAME?: string[];
    MX?: string[];
    NS?: string[];
    TXT?: string[];
  };
}

/** A subdomain confirmed reachable over HTTP(S) during the live probe. */
export interface LiveHost {
  /** Final URL after redirects. */
  url: string;
  status: number;
  title: string;
  /** `Server` response header ("" if not sent). */
  server: string;
  /** `X-Powered-By` response header (absent if not sent). */
  xPoweredBy?: string;
  /** Resolved IP carried over from Stage 1 ("" if unknown). */
  ip: string;
  responseTimeMs: number;
  /** Content length in bytes (Content-Length header, else measured body size). */
  contentLength?: number;
  /** All response headers captured during the probe (lowercased keys). */
  headers: Record<string, string>;
}

/** Technology stack, exposed paths, and crawled links identified for a live host. */
export interface Fingerprint {
  host: string;
  technologies: { name: string; version?: string }[];
  /** Interesting paths that returned a non-404 response, e.g. "/robots.txt (200)". */
  exposedPaths: string[];
  /** Internal links collected from a shallow (depth-1) crawl of the host. */
  links: string[];
}

/** Severity of a finding, ordered INFO < LOW < MEDIUM < HIGH < CRITICAL. */
export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** A single assessed exposure produced by surface analysis or the port scan. */
export interface Finding {
  host: string;
  title: string;
  severity: Severity;
  description: string;
  recommendation: string;
  /** Optional grouping, e.g. "recon", "network". */
  category?: string;
  /** Set for port-scan findings. */
  port?: number;
  service?: string;
  /** Reference URLs (docs, advisories). */
  references?: string[];
  /** Structured scanner evidence: CWE, instances, confidence, ... (platform scanners). */
  details?: Record<string, unknown>;
}

/** An open TCP port discovered during the port-scan stage. */
export interface OpenPort {
  /** The host:port (or host) that was scanned. */
  host: string;
  port: number;
  service: string;
}

/** Result of the nuclei deep-vuln stage, with graceful-degradation status. */
export interface NucleiResult {
  findings: Finding[];
  status: "ok" | "partial" | "unavailable" | "error";
  message?: string;
}

/** One line of the nuclei NDJSON stream (findings + progress + terminal status). */
export type NucleiEvent =
  | { type: "finding"; finding: Finding }
  | { type: "progress"; message: string }
  | { type: "status"; status: NucleiResult["status"]; message?: string };

/** The complete, persistable result of a scan — the report artifact. */
export interface ScanResult {
  target: string;
  mode: "direct" | "domain";
  scanIntensity: ScanIntensity;
  /** Authorization tier the scan ran under, e.g. "Passive" or "Active (attested)". */
  authTier: string;
  startedAt: string;
  endedAt: string;
  /** Names of the stages that actually ran. */
  stagesRun: string[];
  subdomains: Subdomain[];
  liveHosts: LiveHost[];
  openPorts: OpenPort[];
  fingerprints: Fingerprint[];
  findings: Finding[];
  riskScore: number;
  aiSummary?: string;
}
