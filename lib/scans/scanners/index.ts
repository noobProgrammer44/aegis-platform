import type { ScanType } from "@/types/aegis";
import { EXTRA_SCANNERS } from "./extra";
import { RECON_SCANNERS } from "./recon";
import type { Scanner } from "./types";

export type { Scanner, ScannerContext, ScannerOutput } from "./types";

/** Every scanner the runner can execute, by scan type. */
export const SCANNERS: Partial<Record<ScanType, Scanner>> = {
  DISCOVERY: RECON_SCANNERS.discovery,
  SURFACE: RECON_SCANNERS.surface,
  NMAP: RECON_SCANNERS.ports,
  NUCLEI: RECON_SCANNERS.nuclei,
  TLS: EXTRA_SCANNERS.tls,
  EMAIL: EXTRA_SCANNERS.email,
  TAKEOVER: EXTRA_SCANNERS.takeover,
  JS_SECRETS: EXTRA_SCANNERS.jsSecrets,
  ZAP_PASSIVE: EXTRA_SCANNERS.zapPassive,
  ZAP_ACTIVE: EXTRA_SCANNERS.zapActive,
};
