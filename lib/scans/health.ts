import { newId, type DB } from "@/lib/db/client";
import { upsertHealthSnapshot } from "@/lib/db/repos/health-snapshots";
import { listRisks } from "@/lib/db/repos/risks";
import { listTargets, updateTarget } from "@/lib/db/repos/targets";
import { countScoredRisks, healthFromRisks } from "@/lib/domain/health-score";

/**
 * Recomputes health for the scanned targets and records today's snapshots (per target
 * and for the whole workspace) that the trend charts read.
 */
export function recomputeHealth(db: DB, workspaceId: string, scannedTargetIds: readonly string[], at: string): void {
  const day = at.slice(0, 10);
  const allRisks = listRisks(db, workspaceId);
  const targets = listTargets(db, workspaceId);

  for (const targetId of scannedTargetIds) {
    const own = allRisks.filter((r) => r.targetId === targetId);
    const health = healthFromRisks(own);
    updateTarget(db, workspaceId, targetId, { health, lastScannedAt: at });
    upsertHealthSnapshot(db, {
      workspaceId,
      targetId,
      day,
      ...health,
      counts: countScoredRisks(own),
      assets: 1,
    });
  }

  upsertHealthSnapshot(db, {
    workspaceId,
    targetId: null,
    day,
    ...healthFromRisks(allRisks),
    counts: countScoredRisks(allRisks),
    assets: targets.length,
  });
}

/** Id generator for risks created by a scan merge. */
export const newRiskId = (): string => newId("rsk");
