import { load } from "cheerio";
import pLimit from "p-limit";
import type { LiveHost, Subdomain } from "@/types/recon";

/**
 * Stage 2 — Live probe (ACTIVE).
 *
 * This is the first stage that sends traffic to the TARGET. It opens HTTP and
 * HTTPS connections to each resolved subdomain, so it must only run when active
 * scanning is authorized. The real authorization model lands in Phase 7; for now
 * `activeAllowed` is a hard guard that refuses to run otherwise.
 */

const PROBE_TIMEOUT_MS = 5_000;
const PROBE_CONCURRENCY = 10;
const SCHEMES = ["https", "http"] as const;

export async function probe(
  subdomains: Subdomain[],
  activeAllowed: boolean,
): Promise<LiveHost[]> {
  if (!activeAllowed) {
    throw new Error(
      "Active scanning is not authorized. Enable 'Active scan' before probing live hosts.",
    );
  }

  const targets = subdomains.filter((s) => s.resolves);
  const limit = pLimit(PROBE_CONCURRENCY);

  const tasks: Promise<LiveHost | null>[] = [];
  for (const sub of targets) {
    const ip = sub.records.A?.[0] ?? "";
    for (const scheme of SCHEMES) {
      tasks.push(limit(() => probeOne(`${scheme}://${sub.name}`, ip)));
    }
  }

  const results = await Promise.all(tasks);

  // Dedupe by final URL: http:// and https:// often redirect to the same canonical
  // host, which would otherwise produce duplicate hosts (and duplicate findings).
  const seen = new Set<string>();
  return results.filter((host): host is LiveHost => {
    if (host === null || seen.has(host.url)) return false;
    seen.add(host.url);
    return true;
  });
}

/** Probe a single URL. Returns a LiveHost if it responded, else null. */
async function probeOne(url: string, ip: string): Promise<LiveHost | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  const started = Date.now();

  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "User-Agent": "aegis-eass/0.1 (+active-probe)" },
    });

    const body = await res.text();
    const responseTimeMs = Date.now() - started;

    const title = load(body)("title").first().text().trim();

    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key] = value;
    });

    const headerLength = Number(headers["content-length"]);
    const contentLength =
      Number.isFinite(headerLength) && headerLength > 0
        ? headerLength
        : Buffer.byteLength(body);

    return {
      url: res.url || url,
      status: res.status,
      title,
      server: headers["server"] ?? "",
      xPoweredBy: headers["x-powered-by"] ?? undefined,
      ip,
      responseTimeMs,
      contentLength,
      headers,
    };
  } catch {
    // No response: timeout, connection refused, DNS failure, or TLS error.
    return null;
  } finally {
    clearTimeout(timer);
  }
}
