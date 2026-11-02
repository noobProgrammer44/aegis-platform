import type { DiscoveredDomainInput } from "@/lib/db/repos/discovered-domains";
import type { ScanIntensity } from "@/lib/recon/intensity";
import type { DetectedRisk, Target } from "@/types/aegis";
import type { ScannerInfo } from "../catalog";

/**
 * The interface every scanner implements. Active scanners are only called after the
 * gate (lib/scans/gate.ts) allows the target.
 */

export interface ScannerContext {
  target: Target;
  /** Subdomains found earlier for this target (used by the takeover check). */
  relatedHosts: readonly string[];
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
