import type { Authorization, AuthorizationMethod, Target } from "@/types/aegis";
import { cidrContains, parseCidr, parseIPv4 } from "./network";
import { parseTarget } from "./targets";

/**
 * Who may actively scan what. Pure rules; records come from the authorizations table.
 *
 * Tiers: 0 = passive only, 1 = attested (the user confirmed they're authorized),
 * 2 = proven (DNS TXT ownership check passed, or the target is on the user's own
 * machine / private network). Active scanners need tier 1 or higher. A domain
 * authorization covers its subdomains; an IP covers itself; a CIDR covers its range.
 */

export type Tier = 0 | 1 | 2;
export const ACTIVE_SCAN_MIN_TIER: Tier = 1;

export interface TargetAuthorization {
  tier: Tier;
  method: AuthorizationMethod | null;
  /** The record that grants it (null for local targets and tier 0). */
  record: Authorization | null;
  /** Scope string authorizations for this target are stored under. */
  scope: string;
  /** DNS ownership checks only work for domain scopes. */
  dnsVerifiable: boolean;
}

/** Scope a target's authorization is recorded under: hostname, IPv4 or CIDR (no port, scheme or path). */
export function scopeFor(target: Pick<Target, "target">): string {
  const parsed = parseTarget(target.target);
  return parsed.ok ? parsed.target.host : target.target.toLowerCase();
}

const isDomain = (scope: string) => scope.includes(".") && !/^[\d./]+$/.test(scope);

/** True when an authorization recorded for `scope` covers `host` (hostname or IPv4, no port). */
export function scopeCovers(scope: string, host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  const s = scope.toLowerCase().replace(/\.$/, "");
  if (h === s) return true;
  if (isDomain(s)) return h.endsWith(`.${s}`);
  const cidr = s.includes("/") ? parseCidr(s) : null;
  const address = parseIPv4(h);
  if (cidr && address !== null) return cidrContains(cidr, address);
  // A CIDR target is covered by an authorization for a range that contains it.
  const inner = h.includes("/") ? parseCidr(h) : null;
  return Boolean(cidr && inner && cidrContains(cidr, inner.network) && cidrContains(cidr, inner.network + inner.size - 1));
}

const TIER_OF: Record<AuthorizationMethod, Tier> = { local: 2, dns: 2, attested: 1 };

/** The strongest verified authorization covering a host or target scope. */
export function authorizationFor(
  scope: string,
  isLocal: boolean,
  records: readonly Authorization[],
): TargetAuthorization {
  const dnsVerifiable = isDomain(scope) && !isLocal;
  if (isLocal) return { tier: 2, method: "local", record: null, scope, dnsVerifiable };
  const best = records
    .filter((r) => r.verified && scopeCovers(r.scope, scope))
    .sort((a, b) => TIER_OF[b.method] - TIER_OF[a.method])[0];
  return best
    ? { tier: TIER_OF[best.method], method: best.method, record: best, scope, dnsVerifiable }
    : { tier: 0, method: null, record: null, scope, dnsVerifiable };
}

export function targetAuthorization(target: Pick<Target, "target">, records: readonly Authorization[]): TargetAuthorization {
  const parsed = parseTarget(target.target);
  return authorizationFor(scopeFor(target), parsed.ok && parsed.target.isLocal, records);
}

/** Authorization for a bare host as sent by the quick-scan routes ("host", "host:port" or a URL). */
export function hostAuthorization(rawHost: string, records: readonly Authorization[]): TargetAuthorization {
  const parsed = parseTarget(rawHost);
  if (!parsed.ok) return { tier: 0, method: null, record: null, scope: rawHost, dnsVerifiable: false };
  return authorizationFor(parsed.target.host, parsed.target.isLocal, records);
}

export const DNS_TOKEN_PREFIX = "aegis-verify=";

/** Whether the TXT records published on the domain contain the expected token. */
export function txtRecordsContainToken(records: readonly string[][], token: string): boolean {
  const expected = `${DNS_TOKEN_PREFIX}${token}`;
  // A TXT record can arrive split into several strings; join each record's chunks.
  return records.some((chunks) => chunks.join("").trim() === expected);
}

export const TIER_LABEL: Record<Tier, string> = {
  0: "Not authorized",
  1: "Attested",
  2: "Verified",
};
