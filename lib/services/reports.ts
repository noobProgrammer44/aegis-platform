import type { DB } from "@/lib/db/client";
import { appendAudit } from "@/lib/db/repos/audit-log";
import { createReport, getReport, getReportSnapshot } from "@/lib/db/repos/reports";
import { listRisks } from "@/lib/db/repos/risks";
import { listScans } from "@/lib/db/repos/scans";
import { listTargets } from "@/lib/db/repos/targets";
import { getWorkspace } from "@/lib/db/repos/workspaces";
import { csvCell } from "@/lib/domain/risk-table";
import { asReportSnapshot, buildReportSnapshot, type ReportSnapshot } from "@/lib/domain/report";
import type { Report, ReportFilters, ReportFormat, ReportSection } from "@/types/aegis";

/** Generates and reads reports (server only). */

export function generateReport(
  db: DB,
  workspaceId: string,
  input: { name: string; format: ReportFormat; filters: ReportFilters; sections: ReportSection[]; actor: string },
  now: Date = new Date(),
): Report {
  const snapshot = buildReportSnapshot({
    workspaceName: getWorkspace(db, workspaceId)?.name ?? "Workspace",
    filters: input.filters,
    targets: listTargets(db, workspaceId),
    risks: listRisks(db, workspaceId),
    scans: listScans(db, workspaceId, { limit: 1000 }),
    now,
  });
  const report = createReport(db, workspaceId, {
    name: input.name,
    format: input.format,
    filters: input.filters,
    sections: input.sections,
    snapshot,
  });
  appendAudit(db, workspaceId, {
    actor: input.actor,
    action: "report.created",
    subject: report.id,
    details: { name: report.name, risks: snapshot.risks.length },
  });
  return report;
}

export function loadReport(db: DB, workspaceId: string, id: string): { report: Report; snapshot: ReportSnapshot } | null {
  const report = getReport(db, workspaceId, id);
  const snapshot = report ? asReportSnapshot(getReportSnapshot(db, workspaceId, id)) : null;
  return report && snapshot ? { report, snapshot } : null;
}

const CSV_HEADER = ["Title", "Severity", "Status", "Accepted", "Accepted reason", "Scanner", "Target", "Host", "Port", "First detected", "Last detected", "Description", "Solution"];

export function snapshotToCsv(snapshot: ReportSnapshot): string {
  const rows = snapshot.risks.map((r) =>
    [r.title, r.threatLevel, r.status, r.isAccepted ? "yes" : "no", r.acceptedReason ?? "", r.scanType, r.target, r.host ?? "", r.port ?? "", r.firstDetectedAt, r.lastDetectedAt, r.description, r.solution]
      .map(csvCell)
      .join(","),
  );
  return [CSV_HEADER.join(","), ...rows].join("\r\n") + "\r\n";
}
