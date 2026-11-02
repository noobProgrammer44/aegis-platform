import { ACTIVE_SCAN_MIN_TIER, targetAuthorization } from "@/lib/domain/authorization";
import type { Authorization, Target } from "@/types/aegis";

/**
 * Server-side check before any ACTIVE scanner touches a target. The browser never
 * decides this. A target needs to be local / private-network, attested, or
 * DNS-verified (lib/domain/authorization.ts). Passive scanners don't call this.
 */

export const NOT_AUTHORIZED_REASON =
  "Not authorized for active scanning. Confirm you're authorized or verify ownership on the Targets page.";

export function activeScanAllowed(
  target: Pick<Target, "target">,
  records: readonly Authorization[],
): { allowed: boolean; reason: string | null } {
  const auth = targetAuthorization(target, records);
  return auth.tier >= ACTIVE_SCAN_MIN_TIER
    ? { allowed: true, reason: null }
    : { allowed: false, reason: NOT_AUTHORIZED_REASON };
}
