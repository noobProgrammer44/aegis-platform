import { describe, expect, it } from "vitest";
import {
  createReport,
  deleteReport,
  getReport,
  getReportSnapshot,
  listReports,
  setReportAiSummary,
  DEFAULT_REPORT_FILTERS,
} from "@/lib/db/repos/reports";
import {
  createScheduledReport,
  deleteScheduledReport,
  listDueScheduledReports,
  updateScheduledReport,
} from "@/lib/db/repos/scheduled-reports";
import {
  createScheduledScan,
  deleteScheduledScan,
  getScheduledScan,
  listDueScheduledScans,
  listScheduledScans,
  updateScheduledScan,
} from "@/lib/db/repos/scheduled-scans";
import { createWorkspace } from "@/lib/db/repos/workspaces";
import { useMemoryDb, WS } from "./helpers";

const weekly = (nextRun: string | null) => ({
  name: "Weekly surface",
  schedule: "WEEKLY" as const,
  scanTypes: ["SURFACE" as const, "TLS" as const],
  targetsFilter: { targetIds: [], tags: ["prod"] },
  startAt: "2026-11-01T08:00:00.000Z",
  nextRun,
});

describe("scheduled scans repository", () => {
  const db = useMemoryDb();

  it("creates a schedule with notification defaults", () => {
    const s = createScheduledScan(db(), WS, weekly("2026-11-08T08:00:00.000Z"));
    expect(s).toMatchObject({
      intervalDays: null,
      notifyEmails: [],
      notifyPolicy: "ON_CHANGES",
      lastRan: null,
      enabled: true,
      targetsFilter: { targetIds: [], tags: ["prod"] },
    });
    expect(getScheduledScan(db(), WS, s.id)).toEqual(s);
  });

  it("returns only enabled schedules that are due, across workspaces", () => {
    const other = createWorkspace(db(), "Client B");
    const due = createScheduledScan(db(), WS, weekly("2026-11-02T08:00:00.000Z"));
    const dueElsewhere = createScheduledScan(db(), other.id, weekly("2026-11-02T07:00:00.000Z"));
    createScheduledScan(db(), WS, weekly("2026-11-09T08:00:00.000Z"));
    createScheduledScan(db(), WS, weekly(null));
    const paused = createScheduledScan(db(), WS, weekly("2026-11-01T08:00:00.000Z"));
    updateScheduledScan(db(), WS, paused.id, { enabled: false });

    expect(listDueScheduledScans(db(), "2026-11-02T08:00:00.000Z").map((s) => s.id)).toEqual([
      dueElsewhere.id,
      due.id,
    ]);
  });

  it("advances next run and lists soonest first with finished schedules last", () => {
    const a = createScheduledScan(db(), WS, weekly("2026-11-08T08:00:00.000Z"));
    const once = createScheduledScan(db(), WS, { ...weekly(null), schedule: "ONCE" });
    const b = createScheduledScan(db(), WS, weekly("2026-11-03T08:00:00.000Z"));
    const advanced = updateScheduledScan(db(), WS, b.id, {
      lastRan: "2026-11-03T08:00:00.000Z",
      nextRun: "2026-11-10T08:00:00.000Z",
      name: undefined,
    });

    expect(advanced).toMatchObject({ name: "Weekly surface", lastRan: "2026-11-03T08:00:00.000Z" });
    expect(listScheduledScans(db(), WS).map((s) => s.id)).toEqual([a.id, b.id, once.id]);
    expect(deleteScheduledScan(db(), WS, a.id)).toBe(true);
    expect(getScheduledScan(db(), WS, a.id)).toBeNull();
  });
});

describe("reports repository", () => {
  const db = useMemoryDb();

  it("stores the snapshot separately from the listed report", () => {
    const snapshot = { risks: [{ id: "rsk_1", title: "CVE" }], totals: { HIGH: 1 } };
    const report = createReport(db(), WS, {
      name: "November",
      format: "HTML",
      filters: DEFAULT_REPORT_FILTERS,
      sections: ["executive_summary", "risk_details"],
      snapshot,
    });
    expect(report).toMatchObject({ scheduledReportId: null, aiSummary: null });
    expect(getReport(db(), WS, report.id)).toEqual(report);
    expect(getReportSnapshot(db(), WS, report.id)).toEqual(snapshot);
    expect(listReports(db(), WS)).toEqual([report]);
    expect(getReportSnapshot(db(), WS, "missing")).toBeNull();
  });

  it("sets the AI summary and deletes, scoped to the workspace", () => {
    const report = createReport(db(), WS, {
      name: "R",
      format: "JSON",
      filters: DEFAULT_REPORT_FILTERS,
      sections: [],
      snapshot: {},
    });
    const other = createWorkspace(db(), "Client B");
    expect(setReportAiSummary(db(), other.id, report.id, "x")).toBeNull();
    expect(setReportAiSummary(db(), WS, report.id, "Two high risks.")?.aiSummary).toBe(
      "Two high risks.",
    );
    expect(deleteReport(db(), other.id, report.id)).toBe(false);
    expect(deleteReport(db(), WS, report.id)).toBe(true);
    expect(listReports(db(), WS)).toEqual([]);
  });
});

describe("scheduled reports repository", () => {
  const db = useMemoryDb();

  it("creates, finds due ones, updates and deletes", () => {
    const report = createScheduledReport(db(), WS, {
      name: "Weekly exec",
      format: "HTML",
      filters: DEFAULT_REPORT_FILTERS,
      sections: ["executive_summary"],
      schedule: "WEEKLY",
      emails: ["sec@example.com"],
      startAt: "2026-11-02T09:00:00.000Z",
      nextRun: "2026-11-02T09:00:00.000Z",
    });
    expect(report).toMatchObject({ enabled: true, emails: ["sec@example.com"], lastRan: null });
    expect(listDueScheduledReports(db(), "2026-11-02T08:59:59.999Z")).toEqual([]);
    expect(listDueScheduledReports(db(), "2026-11-02T09:00:00.000Z")).toEqual([report]);

    const updated = updateScheduledReport(db(), WS, report.id, { enabled: false });
    expect(updated?.enabled).toBe(false);
    expect(listDueScheduledReports(db(), "2026-12-01T00:00:00.000Z")).toEqual([]);
    expect(deleteScheduledReport(db(), WS, report.id)).toBe(true);
  });
});
