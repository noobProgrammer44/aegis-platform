import type { Report, ReportFilters, ReportFormat, ReportSection } from "@/types/aegis";
import { newId, nowIso, parseJson, toJson, type DB } from "../client";

/**
 * Generated reports. Each one stores a frozen JSON snapshot of the data it was built
 * from, so a report reads the same later even after risks change or close.
 */

interface ReportRow {
  id: string;
  workspace_id: string;
  name: string;
  format: ReportFormat;
  filters: string;
  sections: string;
  scheduled_report_id: string | null;
  ai_summary: string | null;
  created_at: string;
}

export interface NewReport {
  name: string;
  format: ReportFormat;
  filters: ReportFilters;
  sections: ReportSection[];
  scheduledReportId?: string | null;
  aiSummary?: string | null;
  snapshot: unknown;
}

export const DEFAULT_REPORT_FILTERS: ReportFilters = {
  targets: { targetIds: [], tags: [] },
  threatLevels: [],
  includeAccepted: false,
  includeClosed: false,
};

const LIST_COLUMNS =
  "id, workspace_id, name, format, filters, sections, scheduled_report_id, ai_summary, created_at";

const toReport = (row: ReportRow): Report => ({
  id: row.id,
  workspaceId: row.workspace_id,
  name: row.name,
  format: row.format,
  filters: { ...DEFAULT_REPORT_FILTERS, ...parseJson<Partial<ReportFilters>>(row.filters, {}) },
  sections: parseJson<ReportSection[]>(row.sections, []),
  scheduledReportId: row.scheduled_report_id,
  aiSummary: row.ai_summary,
  createdAt: row.created_at,
});

export function createReport(db: DB, workspaceId: string, input: NewReport): Report {
  const report: Report = {
    id: newId("rpt"),
    workspaceId,
    name: input.name,
    format: input.format,
    filters: { ...input.filters },
    sections: [...input.sections],
    scheduledReportId: input.scheduledReportId ?? null,
    aiSummary: input.aiSummary ?? null,
    createdAt: nowIso(),
  };
  db.prepare(
    `INSERT INTO reports (id, workspace_id, name, format, filters, sections, scheduled_report_id,
       ai_summary, snapshot, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    report.id,
    report.workspaceId,
    report.name,
    report.format,
    toJson(report.filters),
    toJson(report.sections),
    report.scheduledReportId,
    report.aiSummary,
    toJson(input.snapshot ?? null),
    report.createdAt,
  );
  return report;
}

export function getReport(db: DB, workspaceId: string, id: string): Report | null {
  const row = db
    .prepare(`SELECT ${LIST_COLUMNS} FROM reports WHERE workspace_id = ? AND id = ?`)
    .get(workspaceId, id) as ReportRow | undefined;
  return row ? toReport(row) : null;
}

/** The frozen data the report was built from; `null` when the report doesn't exist. */
export function getReportSnapshot(db: DB, workspaceId: string, id: string): unknown {
  const row = db
    .prepare("SELECT snapshot FROM reports WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as { snapshot: string } | undefined;
  return row ? parseJson<unknown>(row.snapshot, null) : null;
}

/** Newest first, without snapshots (they can be large). */
export function listReports(db: DB, workspaceId: string, limit = 200): Report[] {
  const rows = db
    .prepare(
      `SELECT ${LIST_COLUMNS} FROM reports WHERE workspace_id = ?
       ORDER BY created_at DESC, id DESC LIMIT ?`,
    )
    .all(workspaceId, limit) as ReportRow[];
  return rows.map(toReport);
}

export function setReportAiSummary(
  db: DB,
  workspaceId: string,
  id: string,
  aiSummary: string | null,
): Report | null {
  const result = db
    .prepare("UPDATE reports SET ai_summary = ? WHERE workspace_id = ? AND id = ?")
    .run(aiSummary, workspaceId, id);
  return result.changes > 0 ? getReport(db, workspaceId, id) : null;
}

export function deleteReport(db: DB, workspaceId: string, id: string): boolean {
  return (
    db.prepare("DELETE FROM reports WHERE workspace_id = ? AND id = ?").run(workspaceId, id)
      .changes > 0
  );
}
