import type { DB } from "@/lib/db/client";
import { appendAudit } from "@/lib/db/repos/audit-log";
import { createScan } from "@/lib/db/repos/scans";
import { createScheduledScan } from "@/lib/db/repos/scheduled-scans";
import { getTarget, listTargetsMatching } from "@/lib/db/repos/targets";
import { validateSchedule } from "@/lib/domain/schedule";
import { isAvailableScanType, SCANNER_CATALOG, type AvailableScanType } from "@/lib/scans/catalog";
import type { ScanRequest } from "@/lib/validation/scan-request";
import type { Scan, ScanIntensityLevel, ScheduledScan, Target, TargetsFilter } from "@/types/aegis";

/** Turns a validated New Scan request into queued scans or a schedule (server only). */

export function queueScans(
  db: DB,
  workspaceId: string,
  input: { types: readonly AvailableScanType[]; targets: readonly Target[]; intensity: ScanIntensityLevel; actor: string; scheduledBy?: string },
): Scan[] {
  return input.types.map((type) => {
    const scan = createScan(db, workspaceId, {
      type,
      intensity: input.intensity,
      targetIds: input.targets.map((t) => t.id),
      targets: input.targets.map((t) => t.target),
      scheduledBy: input.scheduledBy ?? null,
    });
    appendAudit(db, workspaceId, {
      actor: input.actor,
      action: "scan.requested",
      subject: scan.id,
      details: { type, intensity: input.intensity, targets: scan.targets },
    });
    return scan;
  });
}

function targetsFilterOf(req: ScanRequest): TargetsFilter {
  if (req.targetMode === "all") return { targetIds: [], tags: [] };
  if (req.targetMode === "tags") return { targetIds: [], tags: [...req.tags] };
  return { targetIds: [...req.targetIds], tags: [] };
}

export type ScanRequestOutcome =
  | { kind: "queued"; scans: Scan[] }
  | { kind: "scheduled"; schedule: ScheduledScan }
  | { kind: "error"; message: string };

export function submitScanRequest(db: DB, workspaceId: string, req: ScanRequest, now: Date, actor: string): ScanRequestOutcome {
  const types = [...new Set(req.scanTypes)].filter(isAvailableScanType);
  if (types.length === 0) return { kind: "error", message: "Pick at least one scanner." };
  const filter = targetsFilterOf(req);
  const runNow = req.schedule === "ONCE" && (req.runAt === null || Date.parse(req.runAt) <= now.getTime());

  if (runNow) {
    const targets =
      req.targetMode === "selected"
        ? req.targetIds.map((id) => getTarget(db, workspaceId, id)).filter((t): t is Target => t !== null)
        : listTargetsMatching(db, workspaceId, filter);
    if (targets.length === 0) return { kind: "error", message: "None of those targets exist." };
    return { kind: "queued", scans: queueScans(db, workspaceId, { types, targets, intensity: req.intensity, actor }) };
  }

  const startAt = req.runAt ?? now.toISOString();
  const spec = { schedule: req.schedule, startAt, intervalDays: req.schedule === "CUSTOM" ? req.intervalDays : null };
  const problem = validateSchedule(spec);
  if (problem) return { kind: "error", message: problem };
  const schedule = createScheduledScan(db, workspaceId, {
    name: req.name?.trim() || types.map((t) => SCANNER_CATALOG[t].label).join(", "),
    ...spec,
    scanTypes: types,
    intensity: req.intensity,
    targetsFilter: filter,
    notifyEmails: req.notifyPolicy === "NEVER" ? [] : req.notifyEmails,
    notifyPolicy: req.notifyPolicy,
    nextRun: startAt,
  });
  appendAudit(db, workspaceId, { actor, action: "schedule.created", subject: schedule.id, details: { name: schedule.name, schedule: schedule.schedule } });
  return { kind: "scheduled", schedule };
}
