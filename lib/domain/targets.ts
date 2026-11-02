import type { TargetKind } from "@/types/aegis";
import {
  formatCidr,
  formatIPv4,
  isLocalCidr,
  isLocalHostname,
  isLocalIPv4,
  parseCidr,
  parseIPv4,
} from "./network";

/**
 * Parses what a user types into "Add target": a domain, URL, IPv4 address, CIDR range,
 * or host with a port. Returns the normalized form that is stored and deduplicated on.
 */

export interface ParsedTarget {
  /** Normalized form stored on the Target. */
  target: string;
  kind: TargetKind;
  /** Hostname, IPv4 address or CIDR range, without scheme, port or path. */
  host: string;
  /** Explicit port, or the scheme's default for URLs; null when none applies. */
  port: number | null;
  /** Loopback / private / link-local address or a local hostname (auto-authorized). */
  isLocal: boolean;
}

export type ParseTargetResult = { ok: true; target: ParsedTarget } | { ok: false; error: string };

/** Largest range accepted for one target: a /24 (256 addresses). */
export const MAX_CIDR_ADDRESSES = 256;
export const MAX_TARGETS_PER_PASTE = 500;
const MAX_INPUT_LENGTH = 2048;

const DOMAIN_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
/** A single-label host such as `localhost` or a Docker service name. */
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

const fail = (error: string): ParseTargetResult => ({ ok: false, error });
const ok = (target: ParsedTarget): ParseTargetResult => ({ ok: true, target });

export function parseTarget(raw: string): ParseTargetResult {
  const input = raw.trim();
  if (!input) return fail("Enter a target.");
  if (input.length > MAX_INPUT_LENGTH) return fail("Target is too long.");
  if (SCHEME_RE.test(input)) return parseUrlTarget(input);
  if (/^[\d.]+\/\d+$/.test(input)) return parseCidrTarget(input);
  if (input.includes("/")) return parseUrlTarget(`https://${input}`);
  return parseHostTarget(input);
}

type HostCheck =
  | { ok: true; host: string; family: "ipv4" | "domain" | "label"; isLocal: boolean }
  | { ok: false; error: string };

function checkHostname(raw: string): HostCheck {
  const host = raw.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") || host.includes(":")) {
    return { ok: false, error: "IPv6 targets aren't supported yet." };
  }
  if (host.startsWith("*.")) {
    return {
      ok: false,
      error: "Wildcards aren't supported. Add the domain and run subdomain discovery.",
    };
  }
  const address = parseIPv4(host);
  if (address !== null) {
    return { ok: true, host: formatIPv4(address), family: "ipv4", isLocal: isLocalIPv4(address) };
  }
  if (/^[\d.]+$/.test(host)) return { ok: false, error: `${raw} is not a valid IPv4 address.` };
  if (DOMAIN_RE.test(host)) {
    return { ok: true, host, family: "domain", isLocal: isLocalHostname(host) };
  }
  if (LABEL_RE.test(host)) return { ok: true, host, family: "label", isLocal: true };
  return { ok: false, error: `${raw} is not a valid domain, IPv4 address, URL or CIDR range.` };
}

function parsePort(value: string): number | null {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
}

function parseHostTarget(input: string): ParseTargetResult {
  if (input.startsWith("[") || (input.match(/:/g)?.length ?? 0) > 1) {
    return fail("IPv6 targets aren't supported yet.");
  }
  const withPort = /^(.+):(\d{1,5})$/.exec(input);
  const port = withPort ? parsePort(withPort[2]) : null;
  if (withPort && port === null) return fail(`Port ${withPort[2]} is out of range.`);
  if (!withPort && input.includes(":")) return fail(`${input} has an invalid port.`);

  const check = checkHostname(withPort ? withPort[1] : input);
  if (!check.ok) return fail(check.error);
  // A bare single-label name ("intranet") is a host to probe, not a registrable domain.
  const kind: TargetKind =
    port !== null || check.family === "label" ? "host" : check.family === "ipv4" ? "ipv4" : "domain";
  return ok({
    target: port !== null ? `${check.host}:${port}` : check.host,
    kind,
    host: check.host,
    port,
    isLocal: check.isLocal,
  });
}

function parseUrlTarget(input: string): ParseTargetResult {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return fail(`${input} is not a valid URL.`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return fail("Only http:// and https:// URLs are supported.");
  }
  if (url.username || url.password) return fail("URLs with credentials aren't supported.");

  const check = checkHostname(url.hostname);
  if (!check.ok) return fail(check.error);
  const path = url.pathname === "/" ? "" : url.pathname;
  return ok({
    target: `${url.protocol}//${url.host}${path}${url.search}`,
    kind: "url",
    host: check.host,
    port: url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80,
    isLocal: check.isLocal,
  });
}

function parseCidrTarget(input: string): ParseTargetResult {
  const cidr = parseCidr(input);
  if (!cidr) return fail(`${input} is not a valid CIDR range.`);
  if (cidr.size > MAX_CIDR_ADDRESSES) {
    return fail(`CIDR ranges can cover at most ${MAX_CIDR_ADDRESSES} addresses (/24).`);
  }
  const target = formatCidr(cidr);
  return ok({ target, kind: "cidr", host: target, port: null, isLocal: isLocalCidr(cidr) });
}

export interface ParsedTargetList {
  targets: ParsedTarget[];
  errors: { input: string; error: string }[];
}

/** Bulk paste: one target per line (commas, semicolons and spaces also separate). */
export function parseTargetList(text: string): ParsedTargetList {
  const inputs = text.split(/[\s,;]+/).filter((value) => value.length > 0);
  if (inputs.length > MAX_TARGETS_PER_PASTE) {
    return {
      targets: [],
      errors: [{ input: "", error: `Paste at most ${MAX_TARGETS_PER_PASTE} targets at a time.` }],
    };
  }
  const results = inputs.map((input) => ({ input, result: parseTarget(input) }));
  const valid = results.flatMap(({ result }) => (result.ok ? [result.target] : []));
  // Same normalized string means the same parse, so keeping either duplicate is fine.
  const targets = [...new Map(valid.map((t) => [t.target, t] as const)).values()];
  const errors = results.flatMap(({ input, result }) =>
    result.ok ? [] : [{ input, error: result.error }],
  );
  return { targets, errors };
}
