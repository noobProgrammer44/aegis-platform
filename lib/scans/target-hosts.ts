import { formatIPv4, parseCidr } from "@/lib/domain/network";
import { parseTarget } from "@/lib/domain/targets";
import type { Target } from "@/types/aegis";
import type { Subdomain } from "@/types/recon";

/** What each scanner actually connects to for a stored target. Pure. */

type ScannableTarget = Pick<Target, "target" | "kind">;

/** Hosts to probe: `host` or `host:port`; every address of a CIDR range (minus network/broadcast). */
export function hostsForTarget(target: ScannableTarget): string[] {
  if (target.kind === "url") {
    try {
      return [new URL(target.target).host];
    } catch {
      return [];
    }
  }
  if (target.kind === "cidr") {
    const cidr = parseCidr(target.target);
    if (!cidr) return [];
    const all = Array.from({ length: cidr.size }, (_, i) => cidr.network + i);
    const usable = cidr.prefix <= 30 ? all.slice(1, -1) : all;
    return usable.map(formatIPv4);
  }
  return [target.target];
}

/** The recon probe takes discovery output; a stored target is treated as one resolved name. */
export function toSubdomains(hosts: readonly string[]): Subdomain[] {
  return hosts.map((name) => ({ name, resolves: true, records: {} }));
}

/** Registrable domain to enumerate subdomains of, or null when the target isn't a domain. */
export function discoveryDomain(target: ScannableTarget): string | null {
  if (target.kind === "domain") return target.target;
  if (target.kind !== "url") return null;
  const parsed = parseTarget(target.target);
  if (!parsed.ok || !parsed.target.host.includes(".") || /^[\d.]+$/.test(parsed.target.host)) {
    return null;
  }
  return parsed.target.host;
}
