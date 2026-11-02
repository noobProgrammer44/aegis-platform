import type { Risk, ScanType, Target, ThreatLevel } from "@/types/aegis";
import { severityRank } from "./insights";

/** Filtering, grouping and CSV export for the Risks page and its export route. Pure. */

export type StatusFilter = "OPEN" | "CLOSED" | "ALL";
export type AcceptedFilter = "all" | "accepted" | "unaccepted";
export type RiskGrouping = "none" | "title" | "target";

export interface RiskFilters {
  search: string;
  levels: ThreatLevel[];
  status: StatusFilter;
  accepted: AcceptedFilter;
  scanTypes: ScanType[];
  targetId: string | null;
  tag: string | null;
}

export const DEFAULT_RISK_FILTERS: RiskFilters = {
  search: "",
  levels: [],
  status: "OPEN",
  accepted: "all",
  scanTypes: [],
  targetId: null,
  tag: null,
};

type TargetInfo = Pick<Target, "id" | "target" | "label" | "tags">;

export function filterRisks(
  risks: readonly Risk[],
  targets: ReadonlyMap<string, TargetInfo>,
  filters: RiskFilters,
): Risk[] {
  const query = filters.search.trim().toLowerCase();
  return risks.filter((risk) => {
    const target = targets.get(risk.targetId);
    const d = risk.definition;
    return (
      (filters.status === "ALL" || risk.status === filters.status) &&
      (filters.accepted === "all" || risk.isAccepted === (filters.accepted === "accepted")) &&
      (filters.levels.length === 0 || filters.levels.includes(d.threatLevel)) &&
      (filters.scanTypes.length === 0 || filters.scanTypes.includes(d.scanType)) &&
      (!filters.targetId || risk.targetId === filters.targetId) &&
      (!filters.tag || (target?.tags.includes(filters.tag) ?? false)) &&
      (!query ||
        d.title.toLowerCase().includes(query) ||
        d.description.toLowerCase().includes(query) ||
        (target?.target.toLowerCase().includes(query) ?? false) ||
        (target?.label.toLowerCase().includes(query) ?? false))
    );
  });
}

/** Most severe first, then most recently detected. */
export function sortRisks(risks: readonly Risk[]): Risk[] {
  return [...risks].sort(
    (a, b) =>
      severityRank(a.definition.threatLevel) - severityRank(b.definition.threatLevel) ||
      b.lastDetectedAt.localeCompare(a.lastDetectedAt),
  );
}

export interface RiskGroup {
  key: string;
  label: string;
  /** Worst severity in the group, for its header dot. */
  worst: ThreatLevel;
  risks: Risk[];
}

export function groupRisks(
  risks: readonly Risk[],
  grouping: RiskGrouping,
  targets: ReadonlyMap<string, TargetInfo>,
): RiskGroup[] {
  const sorted = sortRisks(risks);
  if (grouping === "none") {
    return [{ key: "all", label: "All risks", worst: sorted[0]?.definition.threatLevel ?? "LOW", risks: sorted }];
  }
  const keyOf = (r: Risk) => (grouping === "title" ? `${r.definition.scanType}:${r.definition.title}` : r.targetId);
  const labelOf = (r: Risk) => {
    if (grouping === "title") return r.definition.title;
    const t = targets.get(r.targetId);
    return t ? t.label || t.target : "Deleted target";
  };
  const keys = [...new Set(sorted.map(keyOf))];
  return keys.map((key) => {
    const members = sorted.filter((r) => keyOf(r) === key);
    return { key, label: labelOf(members[0]), worst: members[0].definition.threatLevel, risks: members };
  });
}

/** Reads filters from URL search params (dashboard links like ?level=CRITICAL). */
export function filtersFromParams(params: Record<string, string | undefined>): RiskFilters {
  const levels = (params.level ?? "")
    .split(",")
    .filter((l): l is ThreatLevel => ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(l));
  const status = params.status === "CLOSED" || params.status === "ALL" ? params.status : "OPEN";
  const accepted = params.accepted === "1" ? "accepted" : params.accepted === "0" ? "unaccepted" : "all";
  return { ...DEFAULT_RISK_FILTERS, levels, status, accepted, targetId: params.target ?? null };
}

/* ---------- CSV ---------- */

/**
 * Quotes a CSV cell and defuses spreadsheet formulas: scan findings contain text from
 * scanned sites, so a cell starting with = + - @ (or tab / CR) is prefixed with '.
 */
export function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\n\r]/.test(safe) || safe !== text ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export const RISK_CSV_COLUMNS = [
  "Title",
  "Severity",
  "Status",
  "Accepted",
  "Accepted reason",
  "Scanner",
  "Target",
  "Host",
  "Port",
  "First detected",
  "Last detected",
  "Closed",
  "Description",
  "Solution",
] as const;

export function risksToCsv(risks: readonly Risk[], targets: ReadonlyMap<string, TargetInfo>): string {
  const rows = sortRisks(risks).map((r) => {
    const d = r.definition;
    const info = d.additionalInfo;
    return [
      d.title,
      d.threatLevel,
      r.status,
      r.isAccepted ? "yes" : "no",
      r.acceptedReason ?? "",
      d.scanType,
      targets.get(r.targetId)?.target ?? "",
      info.host ?? "",
      info.port ?? "",
      r.firstDetectedAt,
      r.lastDetectedAt,
      r.closedAt ?? "",
      d.description,
      d.solution,
    ]
      .map(csvCell)
      .join(",");
  });
  return [RISK_CSV_COLUMNS.join(","), ...rows].join("\r\n") + "\r\n";
}
