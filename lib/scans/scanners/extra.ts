import pLimit from "p-limit";
import { Agent, fetch } from "undici";
import { parseTarget } from "@/lib/domain/targets";
import type { ScanType, Target } from "@/types/aegis";
import { SCANNER_CATALOG } from "../catalog";
import { evaluateEmailSecurity, lookupEmailDns } from "../checks/email";
import { evaluateJsExposure, findSecrets, firstPartyScripts, sourceMapRef, type SecretHit } from "../checks/js-secrets";
import { checkCname, evaluateTakeover } from "../checks/takeover";
import { evaluateTls, probeTls } from "../checks/tls";
import { runZap, type ZapMode } from "../checks/zap";
import { toDetectedRisks } from "../findings";
import { discoveryDomain, hostsForTarget } from "../target-hosts";
import type { Scanner, ScannerOutput } from "./types";

/** Adapters for the checks in lib/scans/checks: TLS, email, takeover, JS secrets, ZAP. */

const EMPTY = { risks: [], discovered: [] } as const;
const skip = (reason: string, raw: unknown = null): ScannerOutput => ({ ...EMPTY, raw, skipped: reason });

const FETCH_TIMEOUT_MS = 10_000;
// Content checks must still read sites with broken certificates; the TLS scanner reports those.
const lenientTls = new Agent({ connect: { rejectUnauthorized: false } });
const MAX_PAGE_BYTES = 2_000_000;
const MAX_SCRIPT_BYTES = 5_000_000;

async function fetchText(url: string, signal: AbortSignal, maxBytes: number): Promise<{ url: string; status: number; text: string } | null> {
  try {
    const res = await fetch(url, {
      dispatcher: lenientTls,
      redirect: "follow",
      signal: AbortSignal.any([signal, AbortSignal.timeout(FETCH_TIMEOUT_MS)]),
      headers: { "user-agent": "Aegis security scanner" },
    });
    const size = Number(res.headers.get("content-length") ?? 0);
    if (size > maxBytes) return { url: res.url, status: res.status, text: "" };
    const text = (await res.text()).slice(0, maxBytes);
    return { url: res.url, status: res.status, text };
  } catch {
    return null;
  }
}

/** The web root a target serves: its URL, or https:// then http:// on the host. */
async function baseUrl(target: Target, signal: AbortSignal): Promise<string | null> {
  if (target.kind === "url") return target.target;
  const [host] = hostsForTarget(target);
  if (!host) return null;
  for (const scheme of ["https", "http"]) {
    const res = await fetchText(`${scheme}://${host}/`, signal, 1);
    if (res) return `${scheme}://${host}/`;
  }
  return null;
}

function tlsEndpoints(target: Target): { host: string; port: number }[] {
  const parsed = parseTarget(target.target);
  if (!parsed.ok) return [];
  const port = target.kind === "url" || target.kind === "host" ? (parsed.target.port ?? 443) : 443;
  const tlsPort = target.kind === "url" && target.target.startsWith("http://") && port === 80 ? 443 : port;
  return hostsForTarget(target)
    .slice(0, 64)
    .map((h) => ({ host: h.replace(/:\d+$/, ""), port: tlsPort }));
}

const tls: Scanner = {
  ...SCANNER_CATALOG.TLS,
  async run({ target, progress }) {
    const endpoints = tlsEndpoints(target);
    progress(`Checking TLS on ${endpoints.length} endpoint${endpoints.length === 1 ? "" : "s"}`);
    const limit = pLimit(8);
    const probes = await Promise.all(endpoints.map((e) => limit(() => probeTls(e.host, e.port))));
    if (!probes.some((p) => p.reachable)) return skip(`No TLS service answered on port ${endpoints[0]?.port ?? 443}.`, probes);
    const now = new Date();
    return { risks: toDetectedRisks("TLS", target.id, probes.flatMap((p) => evaluateTls(p, now))), discovered: [], raw: probes };
  },
};

const email: Scanner = {
  ...SCANNER_CATALOG.EMAIL,
  async run({ target, progress }) {
    const domain = discoveryDomain(target);
    if (!domain) return skip("Email security checks need a domain target.");
    progress(`Reading SPF and DMARC for ${domain}`);
    const records = await lookupEmailDns(domain);
    return { risks: toDetectedRisks("EMAIL", target.id, evaluateEmailSecurity(domain, records)), discovered: [], raw: records };
  },
};

const takeover: Scanner = {
  ...SCANNER_CATALOG.TAKEOVER,
  async run({ target, relatedHosts, progress }) {
    const own = discoveryDomain(target);
    const hosts = [...new Set([...(own ? [own] : []), ...relatedHosts])];
    if (hosts.length === 0) return skip("Takeover checks need a domain target or its discovered subdomains.");
    progress(`Checking CNAMEs of ${hosts.length} host${hosts.length === 1 ? "" : "s"}`);
    const limit = pLimit(10);
    const checks = await Promise.all(hosts.map((h) => limit(() => checkCname(h))));
    const findings = checks.flatMap((c) => evaluateTakeover(c) ?? []);
    return { risks: toDetectedRisks("TAKEOVER", target.id, findings), discovered: [], raw: checks };
  },
};

const jsSecrets: Scanner = {
  ...SCANNER_CATALOG.JS_SECRETS,
  async run({ target, signal, progress }) {
    const base = await baseUrl(target, signal);
    if (!base) return skip("No web server answered on https or http.");
    const page = await fetchText(base, signal, MAX_PAGE_BYTES);
    if (!page) return skip(`Couldn't load ${base}.`);
    const scripts = firstPartyScripts(page.text, page.url);
    progress(`Reading ${scripts.length} script${scripts.length === 1 ? "" : "s"}`);
    const limit = pLimit(4);
    const perScript = await Promise.all(
      scripts.map((url) =>
        limit(async () => {
          const js = await fetchText(url, signal, MAX_SCRIPT_BYTES);
          if (!js || js.status >= 400) return { hits: [] as SecretHit[], map: null as string | null };
          const ref = sourceMapRef(js.text);
          if (ref?.startsWith("data:")) return { hits: findSecrets(js.text, url), map: `${url} (inline)` };
          const candidate = new URL(ref ?? `${url}.map`, url).toString();
          const map = await fetchText(candidate, signal, 64_000);
          const exposed = map && map.status === 200 && map.text.trimStart().startsWith("{") && map.text.includes('"sources"');
          return { hits: findSecrets(js.text, url), map: exposed ? candidate : null };
        }),
      ),
    );
    const hits = [...findSecrets(page.text, page.url), ...perScript.flatMap((s) => s.hits)];
    const maps = perScript.flatMap((s) => (s.map ? [s.map] : []));
    const findings = evaluateJsExposure(new URL(page.url).host, hits, maps);
    return { risks: toDetectedRisks("JS_SECRETS", target.id, findings), discovered: [], raw: { page: page.url, scripts, secrets: hits, sourceMaps: maps } };
  },
};

function zapScanner(type: Extract<ScanType, "ZAP_PASSIVE" | "ZAP_ACTIVE">, mode: ZapMode): Scanner {
  return {
    ...SCANNER_CATALOG[type],
    async run({ target, signal, progress }) {
      const base = await baseUrl(target, signal);
      if (!base) return skip("No web server answered on https or http.");
      progress(mode === "full" ? "Running the ZAP active scan (this can take a while)" : "Running the ZAP baseline scan");
      const result = await runZap(base, mode, signal);
      if (result.status !== "ok") return skip(result.message);
      return { risks: toDetectedRisks(type, target.id, result.findings), discovered: [], raw: result.report };
    },
  };
}

export const EXTRA_SCANNERS = {
  tls,
  email,
  takeover,
  jsSecrets,
  zapPassive: zapScanner("ZAP_PASSIVE", "baseline"),
  zapActive: zapScanner("ZAP_ACTIVE", "full"),
};
