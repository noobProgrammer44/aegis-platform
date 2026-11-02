import { getDb, nowIso, type DB } from "@/lib/db/client";
import { createScan } from "@/lib/db/repos/scans";
import { listDueScheduledScans, updateScheduledScan } from "@/lib/db/repos/scheduled-scans";
import { listTargetsMatching } from "@/lib/db/repos/targets";
import { nextRunAfter } from "@/lib/domain/schedule";
import { pumpQueue } from "./runner";

/** Turns due scheduled scans into queued scans, then advances each schedule. */

const TICK_MS = 30_000;

export function queueDueSchedules(db: DB, now: string): number {
  let queued = 0;
  for (const schedule of listDueScheduledScans(db, now)) {
    const targets = listTargetsMatching(db, schedule.workspaceId, schedule.targetsFilter);
    if (targets.length > 0) {
      for (const type of schedule.scanTypes) {
        createScan(db, schedule.workspaceId, {
          type,
          intensity: schedule.intensity,
          targetIds: targets.map((t) => t.id),
          targets: targets.map((t) => t.target),
          scheduledBy: schedule.id,
        });
        queued += 1;
      }
    }
    updateScheduledScan(db, schedule.workspaceId, schedule.id, {
      lastRan: now,
      nextRun: nextRunAfter(schedule, now),
    });
  }
  return queued;
}

const globalForScheduler = globalThis as unknown as { __aegisScheduler?: ReturnType<typeof setInterval> };

/** Started once from instrumentation.ts when the Node server boots. */
export function startScheduler(): void {
  if (globalForScheduler.__aegisScheduler) return;
  const tick = () => {
    try {
      const db = getDb();
      queueDueSchedules(db, nowIso());
      pumpQueue(db);
    } catch (err) {
      process.stderr.write(`[aegis] scheduler tick failed: ${err instanceof Error ? err.message : String(err)}\n`);
    }
  };
  tick();
  globalForScheduler.__aegisScheduler = setInterval(tick, TICK_MS);
}
