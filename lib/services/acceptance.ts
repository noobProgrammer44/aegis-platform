import { nowIso, type DB } from "@/lib/db/client";
import { listAcceptanceRules } from "@/lib/db/repos/acceptance-rules";
import { listRisks, saveRisks } from "@/lib/db/repos/risks";
import { listTargets } from "@/lib/db/repos/targets";
import { applyAcceptanceRules } from "@/lib/domain/acceptance";
import { recomputeHealth } from "@/lib/scans/health";

/**
 * Re-applies the workspace's enabled acceptance rules to every open risk (after a rule
 * is created, changed or removed) and refreshes health for the targets that changed.
 * Manual acceptances are never touched. Returns how many risks changed.
 */
export function reapplyAcceptanceRules(db: DB, workspaceId: string): number {
  const at = nowIso();
  const rules = listAcceptanceRules(db, workspaceId, { enabledOnly: true });
  const targets = new Map(listTargets(db, workspaceId).map((t) => [t.id, t] as const));
  const open = listRisks(db, workspaceId, { status: "OPEN" });
  const changed = open
    .map((risk) => ({ before: risk, after: applyAcceptanceRules(risk, rules, targets.get(risk.targetId) ?? null, at) }))
    .filter(({ before, after }) => before !== after)
    .map(({ after }) => after);
  if (changed.length === 0) return 0;
  db.transaction(() => {
    saveRisks(db, changed);
    recomputeHealth(db, workspaceId, [...new Set(changed.map((r) => r.targetId))], at);
  })();
  return changed.length;
}
