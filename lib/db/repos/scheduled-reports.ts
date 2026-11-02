import type {
  ReportFilters,
  ReportFormat,
  ReportSection,
  Schedule,
  ScheduledReport,
} from "@/types/aegis";
import { newId, nowIso, parseJson, toBool, toJson, type DB } from "../client";
import { definedOnly } from "../sql";
import { DEFAULT_REPORT_FILTERS } from "./reports";

interface ScheduledReportRow {
  id: string;
  workspace_id: string;
  name: string;
  format: ReportFormat;
  filters: string;
  sections: string;
  schedule: Schedule;
  interval_days: number | null;
  emails: string;
  start_at: string;
  next_run: string | null;
  last_ran: string | null;
  enabled: number;
  created_at: string;
}

export interface NewScheduledReport {
  name: string;
  format: ReportFormat;
  filters: ReportFilters;
  sections: ReportSection[];
  schedule: Schedule;
  intervalDays?: number | null;
  emails?: string[];
  startAt: string;
  nextRun: string | null;
}

export type ScheduledReportPatch = Partial<
  Omit<ScheduledReport, "id" | "workspaceId" | "createdAt">
>;

const toScheduledReport = (row: ScheduledReportRow): ScheduledReport => ({
  id: row.id,
  workspaceId: row.workspace_id,
  name: row.name,
  format: row.format,
  filters: { ...DEFAULT_REPORT_FILTERS, ...parseJson<Partial<ReportFilters>>(row.filters, {}) },
  sections: parseJson<ReportSection[]>(row.sections, []),
  schedule: row.schedule,
  intervalDays: row.interval_days,
  emails: parseJson<string[]>(row.emails, []),
  startAt: row.start_at,
  nextRun: row.next_run,
  lastRan: row.last_ran,
  enabled: toBool(row.enabled),
  createdAt: row.created_at,
});

const toParams = (r: ScheduledReport) => ({
  id: r.id,
  workspace_id: r.workspaceId,
  name: r.name,
  format: r.format,
  filters: toJson(r.filters),
  sections: toJson(r.sections),
  schedule: r.schedule,
  interval_days: r.intervalDays,
  emails: toJson(r.emails),
  start_at: r.startAt,
  next_run: r.nextRun,
  last_ran: r.lastRan,
  enabled: r.enabled ? 1 : 0,
  created_at: r.createdAt,
});

export function createScheduledReport(
  db: DB,
  workspaceId: string,
  input: NewScheduledReport,
): ScheduledReport {
  const scheduled: ScheduledReport = {
    id: newId("srp"),
    workspaceId,
    name: input.name,
    format: input.format,
    filters: { ...input.filters },
    sections: [...input.sections],
    schedule: input.schedule,
    intervalDays: input.intervalDays ?? null,
    emails: [...(input.emails ?? [])],
    startAt: input.startAt,
    nextRun: input.nextRun,
    lastRan: null,
    enabled: true,
    createdAt: nowIso(),
  };
  db.prepare(
    `INSERT INTO scheduled_reports (id, workspace_id, name, format, filters, sections, schedule,
       interval_days, emails, start_at, next_run, last_ran, enabled, created_at)
     VALUES (@id, @workspace_id, @name, @format, @filters, @sections, @schedule, @interval_days,
       @emails, @start_at, @next_run, @last_ran, @enabled, @created_at)`,
  ).run(toParams(scheduled));
  return scheduled;
}

export function getScheduledReport(
  db: DB,
  workspaceId: string,
  id: string,
): ScheduledReport | null {
  const row = db
    .prepare("SELECT * FROM scheduled_reports WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as ScheduledReportRow | undefined;
  return row ? toScheduledReport(row) : null;
}

export function listScheduledReports(db: DB, workspaceId: string): ScheduledReport[] {
  const rows = db
    .prepare(
      `SELECT * FROM scheduled_reports WHERE workspace_id = ?
       ORDER BY next_run IS NULL, next_run, created_at`,
    )
    .all(workspaceId) as ScheduledReportRow[];
  return rows.map(toScheduledReport);
}

/** Enabled schedules due at or before `now` (an ISO string), across workspaces. */
export function listDueScheduledReports(db: DB, now: string): ScheduledReport[] {
  const rows = db
    .prepare(
      `SELECT * FROM scheduled_reports
       WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ? ORDER BY next_run`,
    )
    .all(now) as ScheduledReportRow[];
  return rows.map(toScheduledReport);
}

export function updateScheduledReport(
  db: DB,
  workspaceId: string,
  id: string,
  patch: ScheduledReportPatch,
): ScheduledReport | null {
  const current = getScheduledReport(db, workspaceId, id);
  if (!current) return null;
  const next: ScheduledReport = {
    ...current,
    ...definedOnly(patch),
    id: current.id,
    workspaceId: current.workspaceId,
  };
  db.prepare(
    `UPDATE scheduled_reports SET name = @name, format = @format, filters = @filters,
       sections = @sections, schedule = @schedule, interval_days = @interval_days,
       emails = @emails, start_at = @start_at, next_run = @next_run, last_ran = @last_ran,
       enabled = @enabled
     WHERE workspace_id = @workspace_id AND id = @id`,
  ).run(toParams(next));
  return next;
}

export function deleteScheduledReport(db: DB, workspaceId: string, id: string): boolean {
  return (
    db
      .prepare("DELETE FROM scheduled_reports WHERE workspace_id = ? AND id = ?")
      .run(workspaceId, id).changes > 0
  );
}
