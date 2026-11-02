/**
 * OWASP Top 10 (2021) categories, attached to risks only where the mapping is certain:
 * ZAP's own alert tags for its header / cookie rules, and the CWE of findings our own
 * scanners raise. Anything else gets no category rather than a guess.
 */

export interface OwaspCategory {
  code: string;
  name: string;
  url: string;
}

const CATEGORIES = {
  A01: { code: "A01:2021", name: "Broken Access Control", url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
  A02: { code: "A02:2021", name: "Cryptographic Failures", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
  A05: { code: "A05:2021", name: "Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  A07: { code: "A07:2021", name: "Identification and Authentication Failures", url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" },
} as const satisfies Record<string, OwaspCategory>;

/** ZAP passive rules tagged OWASP_2021_A05 (security headers and cookie flags). */
const ZAP_PLUGIN_CATEGORY: Record<string, OwaspCategory> = {
  "10010": CATEGORIES.A05, // Cookie no HttpOnly flag
  "10011": CATEGORIES.A05, // Cookie without Secure flag
  "10020": CATEGORIES.A05, // Missing anti-clickjacking header
  "10021": CATEGORIES.A05, // X-Content-Type-Options header missing
  "10035": CATEGORIES.A05, // Strict-Transport-Security header not set
  "10036": CATEGORIES.A05, // Server leaks version via "Server" header
  "10038": CATEGORIES.A05, // Content Security Policy header not set
  "10054": CATEGORIES.A05, // Cookie without SameSite attribute
};

export const owaspForZapPlugin = (pluginId: string | undefined): OwaspCategory | null =>
  (pluginId && ZAP_PLUGIN_CATEGORY[pluginId]) || null;

/** Categories for the CWEs our own scanners report. */
export const OWASP = {
  cryptographicFailures: CATEGORIES.A02,
  hardCodedCredentials: CATEGORIES.A07,
  sensitiveInfoInSource: CATEGORIES.A01,
};

export const cweUrl = (id: string | number) => `https://cwe.mitre.org/data/definitions/${id}.html`;
export const zapAlertUrl = (pluginId: string) => `https://www.zaproxy.org/docs/alerts/${pluginId}/`;
