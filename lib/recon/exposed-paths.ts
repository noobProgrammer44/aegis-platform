/**
 * Which sensitive paths the surface scan probes, and whether a response really
 * exposes one. Pure, so the false-positive rules are unit tested.
 */

export const EXPOSED_PATHS = [
  "/.git/config",
  "/.env",
  "/robots.txt",
  "/sitemap.xml",
  "/admin",
  "/swagger",
  "/api-docs",
] as const;

// Paths that should answer with a file, not an HTML page. An HTML 200 here means
// a catch-all is serving the app, which is a false positive rather than a real exposure.
const FILE_LIKE_PATHS = new Set<string>(["/.git/config", "/.env", "/robots.txt", "/sitemap.xml"]);

// Secret files only count when the body looks like the real thing.
const CONTENT_SIGNATURES: Record<string, RegExp> = {
  "/.git/config": /^\s*\[(core|remote|branch)\b/m,
  "/.env": /^\s*[A-Z][A-Z0-9_]*\s*=/m,
};

export interface PathResponse {
  status: number;
  contentType: string;
  body: string;
}

function looksLikeHtml(res: PathResponse): boolean {
  return res.contentType.includes("text/html") || /^\s*<(?:!doctype|html)/i.test(res.body);
}

const ok = (res: PathResponse) => res.status >= 200 && res.status < 300;

/** Random path probed first; if it answers 200, the site serves a catch-all page. */
export const BASELINE_PATH = `/aegis-not-a-page-${Math.random().toString(36).slice(2, 10)}`;
const CATCH_ALL_SIZE_TOLERANCE = 0.05;

/** Same kind of page as the made-up path, and within 5% of its size. */
function looksLikeCatchAll(res: PathResponse, baseline: PathResponse): boolean {
  if (!ok(baseline) || looksLikeHtml(res) !== looksLikeHtml(baseline)) return false;
  const largest = Math.max(res.body.length, baseline.body.length, 1);
  return Math.abs(res.body.length - baseline.body.length) / largest <= CATCH_ALL_SIZE_TOLERANCE;
}

/**
 * True when the path is genuinely reachable. 401 / 403 / 429 / 5xx mean the server
 * or a WAF blocked it (e.g. Cloudflare's 403 page), which is the desired state.
 */
export function isExposedResponse(
  path: string,
  res: PathResponse,
  rootBody: string,
  baseline: PathResponse | null = null,
): boolean {
  if (!ok(res)) return false;
  // SPA catch-all: an unknown path served the root shell, so it isn't a real resource.
  if (res.body.trim() === rootBody.trim()) return false;
  if (baseline && looksLikeCatchAll(res, baseline)) return false;
  if (FILE_LIKE_PATHS.has(path) && looksLikeHtml(res)) return false;
  const signature = CONTENT_SIGNATURES[path];
  return signature ? signature.test(res.body) : true;
}
