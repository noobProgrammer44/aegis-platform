/**
 * Scan intensity ("low and slow" rate control) — a single setting that governs
 * how hard every ACTIVE stage hits a target. Applied consistently across probe,
 * fingerprint, port scan, and nuclei so a scan can be run gently (polite) to
 * avoid blocking/hammering, or fast (aggressive) when speed matters.
 */

export type ScanIntensity = "polite" | "normal" | "aggressive";

export interface IntensityProfile {
  label: string;
  /** p-limit concurrency for the Node stages (probe / fingerprint / ports). */
  concurrency: number;
  /** Inter-request delay (ms) applied before each request — the "slow" lever. */
  delayMs: number;
  /** nuclei -rate-limit (requests/sec). */
  nucleiRateLimit: number;
  /** nuclei -concurrency (parallel templates). */
  nucleiConcurrency: number;
}

export const INTENSITY_PROFILES: Record<ScanIntensity, IntensityProfile> = {
  polite: {
    label: "Polite",
    concurrency: 4,
    delayMs: 250,
    nucleiRateLimit: 20,
    nucleiConcurrency: 10,
  },
  normal: {
    label: "Normal",
    concurrency: 12,
    delayMs: 50,
    nucleiRateLimit: 60,
    nucleiConcurrency: 20,
  },
  aggressive: {
    label: "Aggressive",
    concurrency: 30,
    delayMs: 0,
    nucleiRateLimit: 150,
    nucleiConcurrency: 30,
  },
};

export const DEFAULT_INTENSITY: ScanIntensity = "polite";

/** Normalize untrusted input into a valid intensity (defaults to polite). */
export function resolveIntensity(value: unknown): ScanIntensity {
  return value === "normal" || value === "aggressive" ? value : DEFAULT_INTENSITY;
}

export function intensityProfile(value: unknown): IntensityProfile {
  return INTENSITY_PROFILES[resolveIntensity(value)];
}

/** Small await-able delay used to pace requests under the intensity setting. */
export const delay = (ms: number): Promise<void> =>
  ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve();
