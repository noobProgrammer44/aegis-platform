import { parseTarget } from "@/lib/domain/targets";
import type { Target } from "@/types/aegis";

/**
 * Server-side check before any ACTIVE scanner touches a target. The browser never
 * decides this.
 *
 * Until attestation and DNS ownership verification exist (plan item 3), the only
 * targets authorized automatically are the ones on your own machine or network:
 * loopback, RFC 1918 private and link-local addresses, and local hostnames. Everything
 * else is skipped with the reason below. Passive scanners don't call this.
 */

export const NOT_AUTHORIZED_REASON =
  "Active scans currently run only on local and private-network targets. " +
  "Ownership verification for other targets isn't available yet.";

export function activeScanAllowed(target: Pick<Target, "target">): { allowed: boolean; reason: string | null } {
  const parsed = parseTarget(target.target);
  if (!parsed.ok) return { allowed: false, reason: parsed.error };
  return parsed.target.isLocal
    ? { allowed: true, reason: null }
    : { allowed: false, reason: NOT_AUTHORIZED_REASON };
}
