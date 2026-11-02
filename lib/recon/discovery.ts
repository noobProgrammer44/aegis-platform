import { Resolver } from "node:dns/promises";
import pLimit from "p-limit";
import type { Subdomain } from "@/types/recon";
import { runSubfinder } from "./subfinder";

/**
 * Stage 1 — Discovery (fully PASSIVE).
 *
 * Enumerates subdomains from Certificate Transparency logs (crt.sh) and resolves
 * their DNS records. It NEVER contacts the target's own hosts: the only network
 * calls are to crt.sh (a third-party CT aggregator) and to DNS resolvers. No
 * HTTP/TCP connection is ever opened to the target or its subdomains — that is
 * Stage 2's job.
 */

const CRT_SH_TIMEOUT_MS = 12_000;
const CRT_SH_ATTEMPTS = 3; // crt.sh frequently 5xx's / returns HTML under load
const DNS_TIMEOUT_MS = 2_500;
const DNS_CONCURRENCY = 20;

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Cap how many subdomains we resolve DNS for, to keep a scan responsive.
 *  All discovered subdomains are still returned; those beyond the cap come back
 *  unresolved (empty records, resolves:false). */
export const DNS_RESOLVE_CAP = 75;

export async function discover(domain: string): Promise<Subdomain[]> {
  // Two passive sources in parallel: crt.sh is often overloaded, subfinder covers
  // many other sources. Either one succeeding is enough; results are merged.
  const [crt, sub] = await Promise.allSettled([fetchCrtShSubdomains(domain), runSubfinder(domain)]);
  const fromSubfinder = sub.status === "fulfilled" && sub.value.status === "ok" ? sub.value.names : null;
  if (crt.status === "rejected" && !fromSubfinder) {
    const why = sub.status === "fulfilled" && sub.value.status !== "ok" ? ` subfinder: ${sub.value.message}` : "";
    throw new Error(`${crt.reason instanceof Error ? crt.reason.message : String(crt.reason)}${why}`);
  }
  const names = [...new Set([...(crt.status === "fulfilled" ? crt.value : []), ...(fromSubfinder ?? [])])].sort();

  const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
  const limit = pLimit(DNS_CONCURRENCY);

  const toResolve = names.slice(0, DNS_RESOLVE_CAP);
  const deferred = names.slice(DNS_RESOLVE_CAP);

  const resolved = await Promise.all(
    toResolve.map((name) => limit(() => resolveSubdomain(resolver, name))),
  );

  const unresolved: Subdomain[] = deferred.map((name) => ({
    name,
    resolves: false,
    records: {},
  }));

  return [...resolved, ...unresolved];
}

/**
 * Query crt.sh's JSON API for all certificates covering `*.domain`, then collect,
 * lowercase, dedupe, and drop wildcard (`*.`) entries. Returns a sorted name list.
 *
 * crt.sh is unreliable under load — it 5xx's and sometimes serves an HTML error
 * page with a 200 — so transient failures are retried with backoff. An empty but
 * well-formed `[]` is treated as a genuine "no results", not retried.
 */
async function fetchCrtShSubdomains(domain: string): Promise<string[]> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;

  let lastError = "unknown error";
  for (let attempt = 1; attempt <= CRT_SH_ATTEMPTS; attempt++) {
    if (attempt > 1) await delay(700 * (attempt - 1));

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CRT_SH_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: {
          "User-Agent": "aegis-eass/0.1 (+passive-recon)",
          Accept: "application/json",
        },
      });

      if (res.status >= 500) {
        lastError = `crt.sh returned HTTP ${res.status}`;
        continue; // transient — retry
      }
      if (!res.ok) {
        throw new Error(`crt.sh returned HTTP ${res.status}`);
      }

      const text = await res.text();
      let rows: Array<{ name_value?: string; common_name?: string }>;
      try {
        rows = JSON.parse(text);
      } catch {
        lastError = "crt.sh returned a non-JSON response";
        continue; // usually a transient HTML error page — retry
      }

      return extractNames(rows, domain);
    } catch (err) {
      lastError =
        err instanceof Error && err.name === "AbortError"
          ? `timed out after ${CRT_SH_TIMEOUT_MS / 1000}s`
          : err instanceof Error
            ? err.message
            : String(err);
      // retry network/timeout errors
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error(
    `crt.sh request failed after ${CRT_SH_ATTEMPTS} attempts (${lastError}). ` +
      `crt.sh is often overloaded — try again, or use a smaller domain.`,
  );
}

/** Collect, lowercase, dedupe, drop wildcards, and keep only in-scope names. */
function extractNames(
  rows: Array<{ name_value?: string; common_name?: string }>,
  domain: string,
): string[] {
  const suffix = domain.toLowerCase();
  const names = new Set<string>();

  for (const row of rows) {
    const candidates: string[] = [];
    if (row.name_value) candidates.push(...row.name_value.split("\n"));
    if (row.common_name) candidates.push(row.common_name);

    for (const raw of candidates) {
      const name = raw.trim().toLowerCase();
      if (!name || name.startsWith("*.")) continue; // drop wildcards
      if (name === suffix || name.endsWith(`.${suffix}`)) names.add(name);
    }
  }

  return [...names].sort();
}

/** Resolve all record types for one name. Missing/failed lookups yield []. */
async function resolveSubdomain(resolver: Resolver, name: string): Promise<Subdomain> {
  const [a, aaaa, cname, mx, ns, txt] = await Promise.all([
    safe(() => resolver.resolve4(name)),
    safe(() => resolver.resolve6(name)),
    safe(() => resolver.resolveCname(name)),
    safe(async () =>
      (await resolver.resolveMx(name)).map((r) => `${r.priority} ${r.exchange}`),
    ),
    safe(() => resolver.resolveNs(name)),
    safe(async () => (await resolver.resolveTxt(name)).map((chunks) => chunks.join(""))),
  ]);

  const records: Subdomain["records"] = {};
  if (a.length) records.A = a;
  if (aaaa.length) records.AAAA = aaaa;
  if (cname.length) records.CNAME = cname;
  if (mx.length) records.MX = mx;
  if (ns.length) records.NS = ns;
  if (txt.length) records.TXT = txt;

  return { name, resolves: Object.keys(records).length > 0, records };
}

/** Run a DNS lookup, swallowing ENOTFOUND/ENODATA/timeout into an empty list. */
async function safe(fn: () => Promise<string[]>): Promise<string[]> {
  try {
    return await fn();
  } catch {
    return [];
  }
}
