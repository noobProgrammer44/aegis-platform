import type { ScanState, ScanType } from "@/types/aegis";

/** Display helpers shared by the dashboard and list pages. */

export const SCAN_TYPE_LABEL: Record<ScanType, string> = {
  SURFACE: "Web surface",
  DISCOVERY: "Subdomain discovery",
  NUCLEI: "Nuclei vulnerability",
  NMAP: "Port scan",
  TLS: "TLS / SSL",
  EMAIL: "Email security",
  TAKEOVER: "Domain takeover",
  JS_SECRETS: "JS secrets & source maps",
  ZAP_PASSIVE: "ZAP passive",
  ZAP_ACTIVE: "ZAP active",
};

export const SCAN_STATE_LABEL: Record<ScanState, string> = {
  QUEUED: "Queued",
  RUNNING: "Running",
  SUCCEEDED: "Succeeded",
  FAILED: "Failed",
  BLOCKED: "Blocked",
  STOPPING: "Stopping",
  STOPPED: "Stopped",
};

const UNITS: readonly [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 86_400],
  ["month", 30 * 86_400],
  ["week", 7 * 86_400],
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
];

const relative = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

/** "3 hours ago", "yesterday", "just now". */
export function timeAgo(iso: string, now: Date = new Date()): string {
  const seconds = Math.round((Date.parse(iso) - now.getTime()) / 1000);
  if (Number.isNaN(seconds)) return "";
  if (Math.abs(seconds) < 60) return "just now";
  const [unit, size] = UNITS.find(([, s]) => Math.abs(seconds) >= s) ?? UNITS[UNITS.length - 1];
  return relative.format(Math.trunc(seconds / size), unit);
}

export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}
