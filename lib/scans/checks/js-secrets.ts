import { load } from "cheerio";
import type { ThreatLevel } from "@/types/aegis";
import type { Finding } from "@/types/recon";

/**
 * "Vibe-code leaks": secrets shipped in public JavaScript and source maps anyone can
 * download. The page and its first-party scripts are fetched like a browser would;
 * matched secrets are only ever stored MASKED (first and last 4 characters).
 */

interface SecretPattern {
  id: string;
  name: string;
  re: RegExp;
  level: ThreatLevel;
  /** Extra check on a match (e.g. decode a JWT); defaults to accepting it. */
  confirm?: (match: string) => boolean;
}

function jwtRole(token: string): string | null {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8")) as { role?: unknown };
    return typeof payload.role === "string" ? payload.role : null;
  } catch {
    return null;
  }
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { id: "private-key", name: "Private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g, level: "CRITICAL" },
  { id: "stripe-secret", name: "Stripe secret key", re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g, level: "CRITICAL" },
  { id: "github-token", name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, level: "CRITICAL" },
  { id: "supabase-service-role", name: "Supabase service_role key", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, level: "CRITICAL", confirm: (m) => jwtRole(m) === "service_role" },
  { id: "aws-access-key", name: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, level: "HIGH" },
  { id: "anthropic-key", name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g, level: "HIGH" },
  { id: "openai-key", name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/g, level: "HIGH", confirm: (m) => !m.startsWith("sk-ant-") },
  { id: "slack-token", name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, level: "HIGH" },
  { id: "sendgrid-key", name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, level: "HIGH" },
  // Browser keys (Maps, Firebase) are public by design; flag them so their restrictions get checked.
  { id: "google-api-key", name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, level: "LOW" },
];

export const maskSecret = (secret: string): string =>
  secret.length > 12 ? `${secret.slice(0, 4)}…${secret.slice(-4)}` : "****";

export interface SecretHit {
  patternId: string;
  name: string;
  level: ThreatLevel;
  masked: string;
  url: string;
}

export function findSecrets(source: string, url: string): SecretHit[] {
  const hits = SECRET_PATTERNS.flatMap((p) =>
    [...source.matchAll(p.re)]
      .map((m) => m[0])
      .filter((m) => (p.confirm ? p.confirm(m) : true))
      .map((m) => ({ patternId: p.id, name: p.name, level: p.level, masked: maskSecret(m), url })),
  );
  return [...new Map(hits.map((h) => [`${h.patternId}|${h.masked}`, h] as const)).values()];
}

/** The sourceMappingURL comment at the end of a script, or null. */
export function sourceMapRef(source: string): string | null {
  const match = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/m.exec(source.slice(-2000));
  return match ? match[1] : null;
}

/** First-party script URLs on a page (same host or a subdomain of the page's host). */
export function firstPartyScripts(html: string, pageUrl: string, limit = 25): string[] {
  const page = new URL(pageUrl);
  const base = page.hostname.replace(/^www\./, "");
  const urls = load(html)("script[src]")
    .toArray()
    .map((el) => {
      try {
        return new URL(String(el.attribs.src), page).toString();
      } catch {
        return null;
      }
    })
    .filter((u): u is string => u !== null)
    .filter((u) => {
      const host = new URL(u).hostname;
      return host === page.hostname || host === base || host.endsWith(`.${base}`);
    });
  return [...new Set(urls)].slice(0, limit);
}

/** Findings: one per secret type found, one for exposed source maps. Pure. */
export function evaluateJsExposure(host: string, hits: readonly SecretHit[], maps: readonly string[]): Finding[] {
  const byType = [...new Set(hits.map((h) => h.patternId))].map((id) => hits.filter((h) => h.patternId === id));
  const secretFindings = byType.map((group): Finding => {
    const first = group[0];
    const where = [...new Set(group.map((h) => h.url))].slice(0, 3).join(", ");
    return {
      host,
      title: `${first.name} exposed in public JavaScript`,
      severity: first.level,
      description:
        `${group.length} ${first.name.toLowerCase()}${group.length === 1 ? "" : "s"} (${group.map((h) => h.masked).slice(0, 3).join(", ")}) ` +
        `found in ${where}. Anyone can download these files and read the key.`,
      recommendation:
        first.level === "LOW"
          ? "Browser keys are public by design: restrict this key to your domains and APIs in its console."
          : "Revoke and rotate the key now, then move the call that needs it to your server.",
      category: "js-secrets",
    };
  });
  const mapFindings: Finding[] =
    maps.length === 0
      ? []
      : [
          {
            host,
            title: "JavaScript source maps are publicly downloadable",
            severity: "MEDIUM",
            description: `${maps.length} source map${maps.length === 1 ? "" : "s"} can be downloaded (${maps.slice(0, 3).join(", ")}), exposing original source code, comments and internal paths.`,
            recommendation: "Don't deploy .map files to production, or restrict them to your error-tracking service.",
            category: "js-secrets",
          },
        ];
  return [...secretFindings, ...mapFindings];
}
