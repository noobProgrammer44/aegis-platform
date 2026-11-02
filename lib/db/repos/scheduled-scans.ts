import type {
  NotifyPolicy,
  Schedule,
  ScanType,
  ScheduledScan,
  TargetsFilter,
} from "@/types/aegis";
import { newId, nowIso, parseJson, toBool, toJson, type DB } from "../client";
import { definedOnly } from "../sql";

interface ScheduledScanRow {
  id: string;
  workspace_id: string;
  name: string;
  schedule: Schedule;
  interval_days: number | null;
  scan_types: string;
  targets_filter: string;
  notify_emails: string;
  notify_policy: NotifyPolicy;
  start_at: string;
  next_run: string | null;
  last_ran: string | null;
  enabled: number;
  created_at: string;
}

export interface NewScheduledScan {
  name: string;
  schedule: Schedule;
  intervalDays?: number | null;
  scanTypes: ScanType[];
  targetsFilter: TargetsFilter;
  notifyEmails?: string[];
  notifyPolicy?: NotifyPolicy;
  startAt: string;
  /** First run time; usually `startAt`. */
  nextRun: string | null;
}

export type ScheduledScanPatch = Partial<
  Omit<ScheduledScan, "id" | "workspaceId" | "createdAt">
>;

const EMPTY_FILTER: TargetsFilter = { targetIds: [], tags: [] };

const toScheduledScan = (row: ScheduledScanRow): ScheduledScan => ({
  id: row.id,
  workspaceId: row.workspace_id,
  name: row.name,
  schedule: row.schedule,
  intervalDays: row.interval_days,
  scanTypes: parseJson<ScanType[]>(row.scan_types, []),
  targetsFilter: { ...EMPTY_FILTER, ...parseJson<Partial<TargetsFilter>>(row.targets_filter, {}) },
  notifyEmails: parseJson<string[]>(row.notify_emails, []),
  notifyPolicy: row.notify_policy,
  startAt: row.start_at,
  nextRun: row.next_run,
  lastRan: row.last_ran,
  enabled: toBool(row.enabled),
  createdAt: row.created_at,
});

const toParams = (s: ScheduledScan) => ({
  id: s.id,
  workspace_id: s.workspaceId,
  name: s.name,
  schedule: s.schedule,
  interval_days: s.intervalDays,
  scan_types: toJson(s.scanTypes),
  targets_filter: toJson(s.targetsFilter),
  notify_emails: toJson(s.notifyEmails),
  notify_policy: s.notifyPolicy,
  start_at: s.startAt,
  next_run: s.nextRun,
  last_ran: s.lastRan,
  enabled: s.enabled ? 1 : 0,
  created_at: s.createdAt,
});

export function createScheduledScan(
  db: DB,
  workspaceId: string,
  input: NewScheduledScan,
): ScheduledScan {
  const scheduled: ScheduledScan = {
    id: newId("sch"),
    workspaceId,
    name: input.name,
    schedule: input.schedule,
    intervalDays: input.intervalDays ?? null,
    scanTypes: [...input.scanTypes],
    targetsFilter: {
      targetIds: [...input.targetsFilter.targetIds],
      tags: [...input.targetsFilter.tags],
    },
    notifyEmails: [...(input.notifyEmails ?? [])],
    notifyPolicy: input.notifyPolicy ?? "ON_CHANGES",
    startAt: input.startAt,
    nextRun: input.nextRun,
    lastRan: null,
    enabled: true,
    createdAt: nowIso(),
  };
  db.prepare(
    `INSERT INTO scheduled_scans (id, workspace_id, name, schedule, interval_days, scan_types,
       targets_filter, notify_emails, notify_policy, start_at, next_run, last_ran, enabled,
       created_at)
     VALUES (@id, @workspace_id, @name, @schedule, @interval_days, @scan_types, @targets_filter,
       @notify_emails, @notify_policy, @start_at, @next_run, @last_ran, @enabled, @created_at)`,
  ).run(toParams(scheduled));
  return scheduled;
}

export function getScheduledScan(db: DB, workspaceId: string, id: string): ScheduledScan | null {
  const row = db
    .prepare("SELECT * FROM scheduled_scans WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as ScheduledScanRow | undefined;
  return row ? toScheduledScan(row) : null;
}

/** Soonest next run first; schedules with no next run (finished one-time scans) last. */
export function listScheduledScans(db: DB, workspaceId: string): ScheduledScan[] {
  const rows = db
    .prepare(
      `SELECT * FROM scheduled_scans WHERE workspace_id = ?
       ORDER BY next_run IS NULL, next_run, created_at`,
    )
    .all(workspaceId) as ScheduledScanRow[];
  return rows.map(toScheduledScan);
}

/** Enabled schedules due at or before `now`, across every workspace (scheduler only). */
export function listDueScheduledScans(db: DB, now: string): ScheduledScan[] {
  const rows = db
    .prepare(
      `SELECT * FROM scheduled_scans
       WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ? ORDER BY next_run`,
    )
    .all(now) as ScheduledScanRow[];
  return rows.map(toScheduledScan);
}

export function updateScheduledScan(
  db: DB,
  workspaceId: string,
  id: string,
  patch: ScheduledScanPatch,
): ScheduledScan | null {
  const current = getScheduledScan(db, workspaceId, id);
  if (!current) return null;
  const next: ScheduledScan = {
    ...current,
    ...definedOnly(patch),
    id: current.id,
    workspaceId: current.workspaceId,
  };
  db.prepare(
    `UPDATE scheduled_scans SET name = @name, schedule = @schedule, interval_days = @interval_days,
       scan_types = @scan_types, targets_filter = @targets_filter, notify_emails = @notify_emails,
       notify_policy = @notify_policy, start_at = @start_at, next_run = @next_run,
       last_ran = @last_ran, enabled = @enabled
     WHERE workspace_id = @workspace_id AND id = @id`,
  ).run(toParams(next));
  return next;
}

export function deleteScheduledScan(db: DB, workspaceId: string, id: string): boolean {
  return (
    db
      .prepare("DELETE FROM scheduled_scans WHERE workspace_id = ? AND id = ?")
      .run(workspaceId, id).changes > 0
  );
}
