import type { ScanType } from "@/types/aegis";

/**
 * What each available scanner is called and does. Browser-safe (no scanner code), so
 * the New Scan dialog can list them; lib/scans/scanners.ts holds the implementations.
 */

export type ScannerMode = "passive" | "active";

export interface ScannerInfo {
  type: ScanType;
  label: string;
  description: string;
  mode: ScannerMode;
}

export const SCANNER_CATALOG = {
  SURFACE: {
    type: "SURFACE",
    label: "Web surface",
    description: "Live probe, technology fingerprint, security headers, TLS expiry and exposed paths.",
    mode: "active",
  },
  NMAP: {
    type: "NMAP",
    label: "Port scan",
    description: "TCP connect scan of about 90 common ports, flagging exposed databases and admin services.",
    mode: "active",
  },
  NUCLEI: {
    type: "NUCLEI",
    label: "Nuclei vulnerability",
    description: "Community templates for exposures, misconfigurations and default logins (needs Docker).",
    mode: "active",
  },
  DISCOVERY: {
    type: "DISCOVERY",
    label: "Subdomain discovery",
    description: "Certificate transparency logs and DNS. Sends nothing to the target.",
    mode: "passive",
  },
  TLS: {
    type: "TLS",
    label: "TLS / SSL",
    description: "Certificate expiry, trust and hostname, weak keys, and legacy TLS 1.0 / 1.1.",
    mode: "active",
  },
  EMAIL: {
    type: "EMAIL",
    label: "Email security",
    description: "SPF and DMARC records that stop others sending mail as your domain. DNS only.",
    mode: "passive",
  },
  TAKEOVER: {
    type: "TAKEOVER",
    label: "Domain takeover",
    description: "Subdomains pointing at deleted cloud resources (S3, GitHub Pages, Heroku, Azure…). DNS only.",
    mode: "passive",
  },
  JS_SECRETS: {
    type: "JS_SECRETS",
    label: "JS secrets & source maps",
    description: "API keys and private keys in public JavaScript, and downloadable source maps.",
    mode: "active",
  },
  ZAP_PASSIVE: {
    type: "ZAP_PASSIVE",
    label: "OWASP ZAP baseline",
    description: "Crawls the site and applies ZAP's passive rules (needs Docker).",
    mode: "active",
  },
  ZAP_ACTIVE: {
    type: "ZAP_ACTIVE",
    label: "OWASP ZAP full scan",
    description: "ZAP's active scan sends attack payloads; slow and intrusive (needs Docker).",
    mode: "active",
  },
} as const satisfies Partial<Record<ScanType, ScannerInfo>>;

export type AvailableScanType = keyof typeof SCANNER_CATALOG;

/** In the order the New Scan dialog lists them. */
export const AVAILABLE_SCANNERS: readonly ScannerInfo[] = [
  SCANNER_CATALOG.SURFACE,
  SCANNER_CATALOG.NMAP,
  SCANNER_CATALOG.TLS,
  SCANNER_CATALOG.JS_SECRETS,
  SCANNER_CATALOG.NUCLEI,
  SCANNER_CATALOG.ZAP_PASSIVE,
  SCANNER_CATALOG.ZAP_ACTIVE,
  SCANNER_CATALOG.DISCOVERY,
  SCANNER_CATALOG.EMAIL,
  SCANNER_CATALOG.TAKEOVER,
];

/** Scanners that need Docker running (nuclei, ZAP). */
export const DOCKER_SCANNERS: readonly ScanType[] = ["NUCLEI", "ZAP_PASSIVE", "ZAP_ACTIVE"];

export const isAvailableScanType = (value: string): value is AvailableScanType =>
  Object.prototype.hasOwnProperty.call(SCANNER_CATALOG, value);
