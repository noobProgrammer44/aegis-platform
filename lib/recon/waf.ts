import type { Finding } from "@/types/recon";

/**
 * WAF / CDN / block detection. Identifies when a target is fronted by a WAF/CDN
 * or is actively throttling/blocking the scan, from response headers, status
 * codes, and challenge-page bodies. Surfaced as recon-intel findings.
 */

type HeaderMap = Record<string, string>;

const VENDOR_SIGNATURES: { vendor: string; test: (h: HeaderMap) => boolean }[] = [
  {
    vendor: "Cloudflare",
    test: (h) =>
      "cf-ray" in h || "cf-cache-status" in h || /cloudflare/i.test(h["server"] ?? ""),
  },
  {
    vendor: "Akamai",
    test: (h) =>
      "akamai-grn" in h ||
      Object.keys(h).some((k) => k.startsWith("x-akamai")) ||
      /akamai|ghost/i.test(h["server"] ?? ""),
  },
  {
    vendor: "AWS CloudFront",
    test: (h) =>
      "x-amz-cf-id" in h ||
      /cloudfront/i.test(h["via"] ?? "") ||
      /cloudfront/i.test(h["x-cache"] ?? ""),
  },
  {
    vendor: "Fastly",
    test: (h) => /fastly/i.test(`${h["x-served-by"] ?? ""} ${h["via"] ?? ""}`),
  },
  {
    vendor: "Sucuri",
    test: (h) => "x-sucuri-id" in h || "x-sucuri-cache" in h,
  },
  {
    vendor: "Imperva / Incapsula",
    test: (h) =>
      "x-iinfo" in h || Object.keys(h).some((k) => k.startsWith("incap_ses")),
  },
  {
    vendor: "F5 BIG-IP",
    test: (h) => "x-waf-event-info" in h || /big-?ip/i.test(h["server"] ?? ""),
  },
  { vendor: "Vercel", test: (h) => "x-vercel-id" in h },
  {
    vendor: "Netlify",
    test: (h) => "x-nf-request-id" in h || /netlify/i.test(h["server"] ?? ""),
  },
];

const BLOCK_BODY =
  /Attention Required|Just a moment|cf-browser-verification|Access Denied|Request (?:blocked|unsuccessful)|has been blocked|Sucuri WebSite Firewall|Incapsula incident/i;

export interface WafSignal {
  vendor: string | null;
  signals: string[];
}

/** Detect WAF/CDN or block signals from a response. Empty signals => nothing seen. */
export function detectWaf(
  headers: HeaderMap,
  status?: number,
  body?: string,
): WafSignal {
  const signals: string[] = [];
  let vendor: string | null = null;

  for (const sig of VENDOR_SIGNATURES) {
    if (sig.test(headers)) {
      vendor = sig.vendor;
      signals.push(`${sig.vendor} signature in response headers`);
      break;
    }
  }
  if (status === 403 || status === 429 || status === 503) {
    signals.push(`HTTP ${status} (likely block/throttle)`);
  }
  if (body && BLOCK_BODY.test(body)) {
    signals.push("WAF challenge/block page in body");
  }

  return { vendor, signals };
}

/** Build the WAF/block recon finding from detected signals. */
export function wafFinding(host: string, signal: WafSignal): Finding {
  const lead = signal.vendor
    ? `${signal.vendor} detected`
    : "WAF/CDN or throttling behavior detected";
  const detail = signal.signals.length
    ? ` (${signal.signals.join("; ")})`
    : "";
  return {
    host,
    title: "Target behind WAF/CDN — active scan depth limited",
    severity: "INFO",
    category: "recon",
    description: `${lead}${detail}. The target is fronted by a WAF/CDN or is throttling active requests, so deep (active) findings may be incomplete.`,
    recommendation:
      "Active findings may be incomplete; passive results are unaffected. Scan an authorized/owned target or use low intensity for fuller coverage.",
  };
}
