import type { DB } from "@/lib/db/client";
import { listDiscoveredDomains } from "@/lib/db/repos/discovered-domains";
import { listHealthSnapshots } from "@/lib/db/repos/health-snapshots";
import { listRisks } from "@/lib/db/repos/risks";
import { listScans } from "@/lib/db/repos/scans";
import { listScheduledScans } from "@/lib/db/repos/scheduled-scans";
import { listTargets } from "@/lib/db/repos/targets";
import { countScoredRisks, healthFromRisks, type SeverityCounts } from "@/lib/domain/health-score";
import { filterCoversTarget } from "@/lib/domain/targets";
import {
  healthTrend,
  mostCriticalRisk,
  mostFrequentIssue,
  mostVulnerableTarget,
  periodStart,
  topIssues,
  type IssueGroup,
  type Period,
} from "@/lib/domain/insights";
import {
  THREAT_LEVELS,
  type DiscoveredDomain,
  type HealthScore,
  type Risk,
  type Scan,
  type Target,
} from "@/types/aegis";

/** Everything the dashboard renders, loaded in one place (server only). */
export interface DashboardData {
  period: Period;
  health: HealthScore;
  counts: SeverityCounts;
  openTotal: number;
  accepted: number;
  closedInPeriod: number;
  scansInProgress: number;
  scheduledCount: number;
  trend: ReturnType<typeof healthTrend>;
  topIssues: IssueGroup[];
  recentScans: Scan[];
  recentRisks: Risk[];
  discovered: DiscoveredDomain[];
  discoveredTotal: number;
  mostVulnerable: Target | null;
  mostCritical: { risk: Risk; ageDays: number } | null;
  mostFrequent: IssueGroup | null;
  targetsById: ReadonlyMap<string, Target>;
  /** The target the dashboard is narrowed to, or null for the whole workspace. */
  target: Target | null;
  /** Every target, for the filter picker. */
  targets: Target[];
}

const RECENT_LIMIT = 5;

const since = (start: string | null) => (iso: string | null) =>
  iso !== null && (start === null || iso >= start);

export function loadDashboard(
  db: DB,
  workspaceId: string,
  period: Period,
  now: Date,
  targetId: string | null = null,
): DashboardData {
  const start = periodStart(period, now);
  const inPeriod = since(start);
  const targets = listTargets(db, workspaceId);
  const target = targets.find((t) => t.id === targetId) ?? null;
  const risks = listRisks(db, workspaceId, target ? { targetIds: [target.id] } : {});
  const scans = listScans(db, workspaceId, { limit: 200 }).filter((s) => !target || s.targetIds.includes(target.id));
  const discovered = listDiscoveredDomains(db, workspaceId, { unpromotedOnly: true, viaTargetId: target?.id });
  const schedules = listScheduledScans(db, workspaceId).filter((s) => !target || filterCoversTarget(s.targetsFilter, target));
  const health = healthFromRisks(risks);
  const counts = countScoredRisks(risks);
  const openRisks = risks.filter((r) => r.status === "OPEN");

  return {
    period,
    health,
    counts,
    openTotal: THREAT_LEVELS.reduce((sum, level) => sum + counts[level], 0),
    accepted: openRisks.filter((r) => r.isAccepted).length,
    closedInPeriod: risks.filter((r) => r.status === "CLOSED" && inPeriod(r.closedAt)).length,
    scansInProgress: scans.filter((s) => ["QUEUED", "RUNNING", "STOPPING"].includes(s.state)).length,
    scheduledCount: schedules.filter((s) => s.enabled && s.nextRun).length,
    trend: healthTrend(
      health.score,
      listHealthSnapshots(db, workspaceId, { targetId: target?.id ?? null }),
      now,
    ),
    topIssues: topIssues(risks),
    recentScans: scans.filter((s) => inPeriod(s.createdAt)).slice(0, RECENT_LIMIT),
    recentRisks: openRisks
      .filter((r) => inPeriod(r.firstDetectedAt))
      .sort((a, b) => b.firstDetectedAt.localeCompare(a.firstDetectedAt))
      .slice(0, RECENT_LIMIT),
    discovered: discovered.slice(0, RECENT_LIMIT),
    discoveredTotal: discovered.length,
    mostVulnerable: mostVulnerableTarget(target ? [target] : targets),
    mostCritical: mostCriticalRisk(risks, now),
    mostFrequent: mostFrequentIssue(risks),
    targetsById: new Map(targets.map((t) => [t.id, t] as const)),
    target,
    targets,
  };
}

/** A target's label, falling back to the target string. */
export const targetName = (target: Target | undefined): string =>
  target ? target.label || target.target : "Deleted target";
