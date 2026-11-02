import { load } from "cheerio";
import pLimit from "p-limit";
import wappalyzer from "simple-wappalyzer";
import type { Fingerprint, LiveHost } from "@/types/recon";

/**
 * Stage 3 — Crawl + fingerprint (ACTIVE).
 *
 * For each live host: detect technologies (simple-wappalyzer + Server/X-Powered-By
 * headers + <meta generator> + content signatures), handle SPAs by fingerprinting
 * their JS bundles, do a shallow (depth-1) link crawl, and probe a set of
 * interesting paths. Sends traffic to the target, so it is gated by `activeAllowed`.
 */

const FETCH_TIMEOUT_MS = 8_000;
const PATH_TIMEOUT_MS = 5_000;
const HOST_CONCURRENCY = 5;
const SUBREQ_CONCURRENCY = 4;
const MAX_BUNDLES = 5;
const MAX_LINKS = 50;
const SPARSE_THRESHOLD = 3; // below this many root detections => treat as SPA shell
const UA = "aegis-eass/0.1 (+active-fingerprint)";

const EXPOSED_PATHS = [
  "/.git/config",
  "/.env",
  "/robots.txt",
  "/sitemap.xml",
  "/admin",
  "/swagger",
  "/api-docs",
];

// Paths that should answer with a file, not an HTML page. An HTML 200 here means
// a catch-all is serving the app — a false positive, not a real exposure.
const FILE_LIKE_PATHS = new Set(["/.git/config", "/.env", "/robots.txt", "/sitemap.xml"]);

function looksLikeHtml(res: Resource): boolean {
  const contentType = res.headers.get("content-type") ?? "";
  return contentType.includes("text/html") || /^\s*<(?:!doctype|html)/i.test(res.body);
}

// Supplementary content signatures for things a browserless Wappalyzer run can't
// see in raw JS bundles or error pages (SPA frameworks, server error banners).
const CONTENT_SIGNATURES: { name: string; re: RegExp; versionGroup?: number }[] = [
  { name: "Angular", re: /@license\s+Angular\s+v?([\d.]+)/i, versionGroup: 1 },
  { name: "Angular", re: /ng-version="([\d.]+)"/, versionGroup: 1 },
  { name: "Angular", re: /ɵɵdefine|ɵcmp|ɵfac|platformBrowserDynamic|ngDevMode/ },
  { name: "AngularJS", re: /angular\.module\(|ng-app[\s=]/ },
  { name: "React", re: /__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom(?:\.production)?/ },
  { name: "Vue.js", re: /__VUE__|Vue\.config|vue(?:\.runtime)?\.esm/ },
  { name: "webpack", re: /webpackJsonp|__webpack_require__|webpackChunk/ },
  { name: "jQuery", re: /jQuery\s+v?([\d.]+)/, versionGroup: 1 },
  // Express: default "Cannot GET" page, or a leaked stack trace referencing it.
  { name: "Express", re: /Cannot (?:GET|POST|PUT|DELETE|HEAD|OPTIONS) \//i },
  { name: "Express", re: /node_modules[/\\]express[/\\]/i },
];

// Bogus paths used to trigger server error pages. Root-level 404s often hit a
// SPA catch-all, but a bogus API path tends to reach the backend and may leak a
// framework stack trace.
const ERROR_PROBE_PREFIXES = ["", "api/", "rest/"];

type TechMap = Map<string, { name: string; version?: string }>;
type Cheerio = ReturnType<typeof load>;
type Resource = { url: string; status: number; headers: Headers; body: string };

export async function fingerprint(
  hosts: LiveHost[],
  activeAllowed: boolean,
): Promise<Fingerprint[]> {
  if (!activeAllowed) {
    throw new Error(
      "Active scanning is not authorized. Enable 'Active scan' before fingerprinting.",
    );
  }

  const limit = pLimit(HOST_CONCURRENCY);
  return Promise.all(hosts.map((host) => limit(() => fingerprintOne(host))));
}

async function fingerprintOne(host: LiveHost): Promise<Fingerprint> {
  const target = host.url;
  const techs: TechMap = new Map();
  let links: string[] = [];

  const root = await fetchResource(target, FETCH_TIMEOUT_MS);

  if (root) {
    const headers = headersToObject(root.headers);
    await runWappalyzer(techs, root.url, headers, root.body);
    parseServer(techs, root.headers.get("server"));
    parsePoweredBy(techs, root.headers.get("x-powered-by"));

    const $ = load(root.body);
    parseGenerator(techs, $);
    detectFromContent(techs, root.body);
    links = extractLinks($, root.url);

    // SPA handling: a bare shell yields few detections — look inside the bundles.
    if (techs.size < SPARSE_THRESHOLD) {
      await fingerprintBundles(techs, extractScripts($, root.url));
    }

    // Error-page fingerprinting: catches server frameworks (e.g. Express's
    // "Cannot GET" page) even when X-Powered-By is stripped.
    await fingerprintErrorPage(techs, target);
  }

  const exposedPaths = await checkExposedPaths(target, root?.body ?? "");

  return {
    host: target,
    technologies: [...techs.values()].sort((a, b) =>
      a.name.localeCompare(b.name),
    ),
    exposedPaths,
    links,
  };
}

async function fingerprintBundles(techs: TechMap, scripts: string[]) {
  const limit = pLimit(SUBREQ_CONCURRENCY);
  await Promise.all(
    scripts.slice(0, MAX_BUNDLES).map((src) =>
      limit(async () => {
        const bundle = await fetchResource(src, FETCH_TIMEOUT_MS);
        if (bundle?.body) {
          await runWappalyzer(techs, bundle.url, {}, bundle.body);
          detectFromContent(techs, bundle.body);
        }
      }),
    ),
  );
}

async function fingerprintErrorPage(techs: TechMap, baseUrl: string) {
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return;
  }
  const token = `aegis-probe-${Date.now()}`;
  const limit = pLimit(SUBREQ_CONCURRENCY);
  await Promise.all(
    ERROR_PROBE_PREFIXES.map((prefix) =>
      limit(async () => {
        const res = await fetchResource(`${origin}/${prefix}${token}`, PATH_TIMEOUT_MS);
        if (res?.body) {
          await runWappalyzer(techs, res.url, headersToObject(res.headers), res.body);
          detectFromContent(techs, res.body);
        }
      }),
    ),
  );
}

async function checkExposedPaths(
  baseUrl: string,
  rootBody: string,
): Promise<string[]> {
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  const rootNorm = rootBody.trim();
  const limit = pLimit(SUBREQ_CONCURRENCY);

  const results = await Promise.all(
    EXPOSED_PATHS.map((path) =>
      limit(async () => {
        const res = await fetchResource(origin + path, PATH_TIMEOUT_MS);
        if (!res || res.status === 404) return null;
        // SPA catch-all: an unknown path served the root shell -> not a real resource.
        if (res.status === 200 && res.body.trim() === rootNorm) return null;
        // File-like paths (.git/.env/robots/sitemap) that answer with HTML are almost
        // certainly a catch-all/CDN page, not the real file — avoid the false positive.
        if (res.status === 200 && FILE_LIKE_PATHS.has(path) && looksLikeHtml(res)) {
          return null;
        }
        return `${path} (${res.status})`;
      }),
    ),
  );

  return results.filter((r): r is string => r !== null).sort();
}

// --- detection helpers -----------------------------------------------------

async function runWappalyzer(
  map: TechMap,
  url: string,
  headers: Record<string, string>,
  html: string,
) {
  try {
    const detected = await wappalyzer({ url, headers, html });
    for (const tech of detected) addTech(map, tech.name, tech.version);
  } catch {
    // ignore detection failures for a single resource
  }
}

function parseServer(map: TechMap, server: string | null) {
  if (!server) return;
  const match = server.match(/^([A-Za-z][\w.+-]*)(?:\/([\w.]+))?/);
  if (match) addTech(map, match[1], match[2]);
}

function parsePoweredBy(map: TechMap, value: string | null) {
  if (!value) return;
  for (const part of value.split(",")) {
    const match = part.trim().match(/^([A-Za-z][\w.+ -]*?)(?:\/([\w.]+))?$/);
    if (match) addTech(map, match[1].trim(), match[2]);
  }
}

function parseGenerator(map: TechMap, $: Cheerio) {
  $('meta[name="generator"]').each((_, el) => {
    const content = $(el).attr("content")?.trim();
    if (!content) return;
    const match = content.match(/^(.+?)[\s/]+v?([\d.]+)/);
    if (match) addTech(map, match[1].trim(), match[2]);
    else addTech(map, content);
  });
}

function detectFromContent(map: TechMap, content: string) {
  for (const sig of CONTENT_SIGNATURES) {
    const match = content.match(sig.re);
    if (match) addTech(map, sig.name, sig.versionGroup ? match[sig.versionGroup] : undefined);
  }
}

function addTech(map: TechMap, rawName: string, version?: string) {
  const name = rawName.trim();
  if (!name) return;
  const key = name.toLowerCase();
  const existing = map.get(key);
  if (!existing) {
    map.set(key, { name, version: version || undefined });
  } else if (!existing.version && version) {
    existing.version = version;
  }
}

// --- crawl helpers ---------------------------------------------------------

function extractLinks($: Cheerio, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const links = new Set<string>();
  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href) return;
    try {
      const u = new URL(href, baseUrl);
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      if (u.hostname !== base.hostname) return; // internal only
      u.hash = "";
      links.add(u.href);
    } catch {
      // ignore malformed hrefs
    }
  });
  return [...links].slice(0, MAX_LINKS);
}

function extractScripts($: Cheerio, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const scripts = new Set<string>();
  $("script[src]").each((_, el) => {
    const src = $(el).attr("src");
    if (!src) return;
    try {
      const u = new URL(src, baseUrl);
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      if (u.hostname !== base.hostname) return; // same-origin bundles only
      scripts.add(u.href);
    } catch {
      // ignore malformed srcs
    }
  });
  return [...scripts];
}

// --- networking ------------------------------------------------------------

async function fetchResource(
  url: string,
  timeoutMs: number,
): Promise<Resource | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "User-Agent": UA },
    });
    const body = await res.text();
    return { url: res.url || url, status: res.status, headers: res.headers, body };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function headersToObject(headers: Headers): Record<string, string> {
  const obj: Record<string, string> = {};
  headers.forEach((value, key) => {
    obj[key] = value;
  });
  return obj;
}
