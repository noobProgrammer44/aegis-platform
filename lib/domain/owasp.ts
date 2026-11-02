/**
 * OWASP Top 10 (2021) categories, attached to risks only where the mapping is certain:
 * ZAP's own alert tags, and the CWE of findings our own scanners raise. Anything else
 * gets no category rather than a guess.
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

/** OWASP category from a ZAP alert tag such as OWASP_2021_A05 (ZAP's own mapping). */
export function owaspFromZapTag(tag: string, link: string): OwaspCategory | null {
  const match = /^OWASP_2021_A(\d{2})$/.exec(tag);
  if (!match) return null;
  const known = Object.values(CATEGORIES).find((c) => c.code === `A${match[1]}:2021`);
  if (known) return known;
  const slug = /A\d{2}_2021-([^/]+)\/?$/.exec(link)?.[1];
  return { code: `A${match[1]}:2021`, name: slug ? slug.replace(/_/g, " ") : "OWASP Top 10", url: link || "https://owasp.org/Top10/" };
}

/** Categories for the CWEs our own scanners report. */
export const OWASP = {
  cryptographicFailures: CATEGORIES.A02,
  hardCodedCredentials: CATEGORIES.A07,
  sensitiveInfoInSource: CATEGORIES.A01,
};

export const cweUrl = (id: string | number) => `https://cwe.mitre.org/data/definitions/${id}.html`;
export const zapAlertUrl = (pluginId: string) => `https://www.zaproxy.org/docs/alerts/${pluginId}/`;
export const wascUrl = (id: string | number) => `http://projects.webappsec.org/w/page/13246978/Threat%20Classification#${id}`;
