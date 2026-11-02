import { fetch } from "undici";

/**
 * Cloudflare answers on these ports for every proxied hostname, whatever the origin
 * runs, so an open 2083 on a Cloudflare host is its edge, not cPanel.
 * https://developers.cloudflare.com/fundamentals/reference/network-ports/
 */
export const CLOUDFLARE_PROXY_PORTS = new Set([
  80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880,
]);

const PROBE_TIMEOUT_MS = 5000;

/** True when response headers come from Cloudflare's edge. */
export function isCloudflareResponse(headers: Record<string, string>): boolean {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return "cf-ray" in lower || /cloudflare/i.test(lower.server ?? "");
}

/** One HEAD request to the host's web root; any answer with Cloudflare headers counts. */
export async function behindCloudflare(hostname: string): Promise<boolean> {
  for (const scheme of ["https", "http"]) {
    try {
      const res = await fetch(`${scheme}://${hostname}/`, {
        method: "HEAD",
        redirect: "manual",
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      });
      return isCloudflareResponse(Object.fromEntries(res.headers.entries()));
    } catch {
      /* try the next scheme */
    }
  }
  return false;
}
