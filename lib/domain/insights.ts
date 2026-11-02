import {
  THREAT_LEVELS,
  type HealthSnapshot,
  type Risk,
  type ScanType,
  type Target,
  type ThreatLevel,
} from "@/types/aegis";

/** Dashboard insights computed from stored risks and targets. Pure. */

export type Period = "30d" | "90d" | "1y" | "all";

export const PERIODS: readonly { value: Period; label: string; days: number | null }[] = [
  { value: "30d", label: "Last 30 days", days: 30 },
  { value: "90d", label: "Last 90 days", days: 90 },
  { value: "1y", label: "Last year", days: 365 },
  { value: "all", label: "All time", days: null },
];

export const DEFAULT_PERIOD: Period = "1y";
const DAY_MS = 86_400_000;

export function parsePeriod(raw: unknown): Period {
  return PERIODS.some((p) => p.value === raw) ? (raw as Period) : DEFAULT_PERIOD;
}

/** ISO start of the period, or null for all time. */
export function periodStart(period: Period, now: Date): string | null {
  const days = PERIODS.find((p) => p.value === period)?.days ?? null;
  return days === null ? null : new Date(now.getTime() - days * DAY_MS).toISOString();
}

export const severityRank = (level: ThreatLevel): number => THREAT_LEVELS.indexOf(level);

const isScored = (risk: Risk) => risk.status === "OPEN" && !risk.isAccepted;

export interface IssueGroup {
  title: string;
  scanType: ScanType;
  threatLevel: ThreatLevel;
  /** Open, non-accepted occurrences across targets. */
  count: number;
  targetCount: number;
  oldestDetectedAt: string;
}

function groupBy<T>(items: readonly T[], keyOf: (item: T) => string): T[][] {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const key = keyOf(item);
    groups.set(key, [...(groups.get(key) ?? []), item]);
  }
  return [...groups.values()];
}

function toIssueGroup(group: readonly Risk[]): IssueGroup {
  const [first] = group;
  const worst = group.reduce((a, b) =>
    severityRank(b.definition.threatLevel) < severityRank(a.definition.threatLevel) ? b : a,
  );
  return {
    title: first.definition.title,
    scanType: first.definition.scanType,
    threatLevel: worst.definition.threatLevel,
    count: group.length,
    targetCount: new Set(group.map((risk) => risk.targetId)).size,
    oldestDetectedAt: group.map((risk) => risk.firstDetectedAt).sort()[0],
  };
}

/** Open, non-accepted risks grouped by scanner + title, worst first, then most common. */
export function groupOpenIssues(risks: readonly Risk[]): IssueGroup[] {
  return groupBy(risks.filter(isScored), (r) => `${r.definition.scanType}\u0000${r.definition.title}`)
    .map(toIssueGroup)
    .sort(
      (a, b) =>
        severityRank(a.threatLevel) - severityRank(b.threatLevel) ||
        b.count - a.count ||
        a.title.localeCompare(b.title),
    );
}

/** "Top issues dragging down your score". */
export function topIssues(risks: readonly Risk[], limit = 3): IssueGroup[] {
  return groupOpenIssues(risks).slice(0, limit);
}

/** The issue seen on the most occurrences (ties: more severe first). */
export function mostFrequentIssue(risks: readonly Risk[]): IssueGroup | null {
  const sorted = [...groupOpenIssues(risks)].sort(
    (a, b) => b.count - a.count || severityRank(a.threatLevel) - severityRank(b.threatLevel),
  );
  return sorted[0] ?? null;
}

/** The most severe open risk, oldest first among equals, with how long it has been open. */
export function mostCriticalRisk(
  risks: readonly Risk[],
  now: Date,
): { risk: Risk; ageDays: number } | null {
  const [risk] = risks
    .filter(isScored)
    .sort(
      (a, b) =>
        severityRank(a.definition.threatLevel) - severityRank(b.definition.threatLevel) ||
        a.firstDetectedAt.localeCompare(b.firstDetectedAt),
    );
  if (!risk) return null;
  const ageDays = Math.max(0, Math.floor((now.getTime() - Date.parse(risk.firstDetectedAt)) / DAY_MS));
  return { risk, ageDays };
}

/** The target with the worst (highest) health score, if any target has risks. */
export function mostVulnerableTarget(targets: readonly Target[]): Target | null {
  const [worst] = [...targets].sort((a, b) => b.health.score - a.health.score);
  return worst && worst.health.score > 0 ? worst : null;
}

/**
 * Change against the snapshot closest to (on or before) `daysAgo` days back.
 * Positive delta means the score went up, i.e. got worse.
 */
export function healthTrend(
  currentScore: number,
  snapshots: readonly HealthSnapshot[],
  now: Date,
  daysAgo = 30,
): { delta: number; previousScore: number; previousDay: string } | null {
  const cutoff = new Date(now.getTime() - daysAgo * DAY_MS).toISOString().slice(0, 10);
  const previous = [...snapshots]
    .filter((s) => s.day <= cutoff)
    .sort((a, b) => b.day.localeCompare(a.day))[0];
  if (!previous) return null;
  return { delta: currentScore - previous.score, previousScore: previous.score, previousDay: previous.day };
}
