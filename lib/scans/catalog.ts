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
} as const satisfies Partial<Record<ScanType, ScannerInfo>>;

export type AvailableScanType = keyof typeof SCANNER_CATALOG;

/** In the order the New Scan dialog lists them. */
export const AVAILABLE_SCANNERS: readonly ScannerInfo[] = [
  SCANNER_CATALOG.SURFACE,
  SCANNER_CATALOG.NMAP,
  SCANNER_CATALOG.NUCLEI,
  SCANNER_CATALOG.DISCOVERY,
];

export const isAvailableScanType = (value: string): value is AvailableScanType =>
  Object.prototype.hasOwnProperty.call(SCANNER_CATALOG, value);
