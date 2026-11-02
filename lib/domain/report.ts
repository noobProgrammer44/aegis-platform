import type {
  HealthScore,
  ReportFilters,
  ReportSection,
  Risk,
  Scan,
  ScanType,
  Target,
  TargetKind,
  ThreatLevel,
} from "@/types/aegis";
import { countScoredRisks, healthFromRisks, type SeverityCounts } from "./health-score";
import { severityRank, topIssues, type IssueGroup } from "./insights";

/**
 * The frozen content of a report. Built once when the report is generated and stored
 * with it, so a report reads the same later even after risks change. Pure.
 */

export const REPORT_SECTIONS: readonly { value: ReportSection; label: string }[] = [
  { value: "executive_summary", label: "Executive summary" },
  { value: "coverage", label: "Coverage" },
  { value: "target_breakdown", label: "Target breakdown" },
  { value: "risk_details", label: "Risk details" },
  { value: "accepted_risks", label: "Accepted risks" },
];

export interface ReportTargetRow {
  id: string;
  name: string;
  target: string;
  kind: TargetKind;
  health: HealthScore;
  counts: SeverityCounts;
  lastScannedAt: string | null;
}

export interface ReportRisk {
  id: string;
  title: string;
  threatLevel: ThreatLevel;
  scanType: ScanType;
  status: Risk["status"];
  isAccepted: boolean;
  acceptedReason: string | null;
  target: string;
  host: string | null;
  port: number | null;
  description: string;
  solution: string;
  references: string[];
  firstDetectedAt: string;
  lastDetectedAt: string;
}

export interface ReportSnapshot {
  version: 1;
  generatedAt: string;
  workspaceName: string;
  filters: ReportFilters;
  health: HealthScore;
  totals: { byLevel: SeverityCounts; included: number; accepted: number; closed: number };
  coverage: {
    targets: number;
    scannedTargets: number;
    scans: number;
    byScanType: { type: ScanType; count: number }[];
    lastScanAt: string | null;
  };
  targets: ReportTargetRow[];
  risks: ReportRisk[];
  topIssues: IssueGroup[];
}

export interface ReportInput {
  workspaceName: string;
  filters: ReportFilters;
  targets: readonly Target[];
  risks: readonly Risk[];
  scans: readonly Scan[];
  now: Date;
}

function selectTargets(targets: readonly Target[], filters: ReportFilters): Target[] {
  const { targetIds, tags } = filters.targets;
  if (targetIds.length === 0 && tags.length === 0) return [...targets];
  return targets.filter((t) => targetIds.includes(t.id) || t.tags.some((tag) => tags.includes(tag)));
}

const includeRisk = (filters: ReportFilters) => (risk: Risk) =>
  (filters.threatLevels.length === 0 || filters.threatLevels.includes(risk.definition.threatLevel)) &&
  (filters.includeClosed || risk.status === "OPEN") &&
  (filters.includeAccepted || !risk.isAccepted);

const toReportRisk = (risk: Risk, target: Target | undefined): ReportRisk => {
  const info = risk.definition.additionalInfo;
  return {
    id: risk.id,
    title: risk.definition.title,
    threatLevel: risk.definition.threatLevel,
    scanType: risk.definition.scanType,
    status: risk.status,
    isAccepted: risk.isAccepted,
    acceptedReason: risk.acceptedReason,
    target: target ? target.label || target.target : "Deleted target",
    host: typeof info.host === "string" ? info.host : null,
    port: typeof info.port === "number" ? info.port : null,
    description: risk.definition.description,
    solution: risk.definition.solution,
    references: [...risk.definition.references],
    firstDetectedAt: risk.firstDetectedAt,
    lastDetectedAt: risk.lastDetectedAt,
  };
};

export function buildReportSnapshot(input: ReportInput): ReportSnapshot {
  const { filters } = input;
  const targets = selectTargets(input.targets, filters);
  const targetIds = new Set(targets.map((t) => t.id));
  const byId = new Map(targets.map((t) => [t.id, t] as const));
  const scoped = input.risks.filter((r) => targetIds.has(r.targetId));
  const included = scoped
    .filter(includeRisk(filters))
    .sort(
      (a, b) =>
        severityRank(a.definition.threatLevel) - severityRank(b.definition.threatLevel) ||
        a.definition.title.localeCompare(b.definition.title),
    );
  const scans = input.scans.filter((s) => s.targetIds.some((id) => targetIds.has(id)));
  const scanTypes = [...new Set(scans.map((s) => s.type))];

  return {
    version: 1,
    generatedAt: input.now.toISOString(),
    workspaceName: input.workspaceName,
    filters,
    health: healthFromRisks(scoped),
    totals: {
      byLevel: countScoredRisks(included.map((r) => ({ ...r, status: "OPEN" as const, isAccepted: false }))),
      included: included.length,
      accepted: scoped.filter((r) => r.status === "OPEN" && r.isAccepted).length,
      closed: scoped.filter((r) => r.status === "CLOSED").length,
    },
    coverage: {
      targets: targets.length,
      scannedTargets: targets.filter((t) => t.lastScannedAt).length,
      scans: scans.length,
      byScanType: scanTypes.map((type) => ({ type, count: scans.filter((s) => s.type === type).length })),
      lastScanAt: scans.map((s) => s.finishedAt ?? s.createdAt).sort().at(-1) ?? null,
    },
    targets: targets
      .map((t) => ({
        id: t.id,
        name: t.label || t.target,
        target: t.target,
        kind: t.kind,
        health: t.health,
        counts: countScoredRisks(scoped.filter((r) => r.targetId === t.id)),
        lastScannedAt: t.lastScannedAt,
      }))
      .sort((a, b) => b.health.score - a.health.score || a.name.localeCompare(b.name)),
    risks: included.map((r) => toReportRisk(r, byId.get(r.targetId))),
    topIssues: topIssues(scoped, 5),
  };
}

/** Narrows stored JSON to a snapshot this version can render. */
export function asReportSnapshot(value: unknown): ReportSnapshot | null {
  const v = value as Partial<ReportSnapshot> | null;
  return v && v.version === 1 && Array.isArray(v.risks) && Array.isArray(v.targets) ? (v as ReportSnapshot) : null;
}
